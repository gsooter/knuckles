"""The ``knuckles`` command: provision and check Knuckles tenants.

Every subcommand takes the global ``--json`` flag, which prints the
Knuckles API envelope (``{"data": ...}`` or ``{"error": {"code",
"message"}}``) so coding agents can parse results. Without it, output
is short human-readable text and errors go to stderr.

Exit codes: 0 success, 1 failure (API error, invalid input, or a
failing ``doctor`` check), 2 usage error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from knuckles_cli import __version__
from knuckles_cli.api import KnucklesAPI
from knuckles_cli.config import (
    Profile,
    config_path,
    normalize_url,
    remove_profile,
    resolve_profile,
    save_profile,
)
from knuckles_cli.doctor import Check, check_app, check_server
from knuckles_cli.envfile import check_env, write_env
from knuckles_cli.errors import (
    EMAIL_DOMAIN_UNVERIFIED,
    INVALID_INPUT,
    CliError,
)
from knuckles_cli.providers import (
    CONFIG_GROUPS,
    apple_key_id_from_filename,
    check_resend_domain,
    email_address_of,
    origin_of,
    parse_google_client_secret,
    passkey_config,
    validate_apple_identifier,
    validate_apple_private_key,
    validate_services_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class Context:
    """Per-invocation state shared by command handlers.

    Attributes:
        as_json: Whether to print JSON envelopes.
        profile: Profile name to read or write.
        config: Path of the profile file.
        env: Process environment.
    """

    as_json: bool
    profile: str
    config: Path
    env: Mapping[str, str]

    def api(self) -> KnucklesAPI:
        """Build an API client from the effective profile.

        Returns:
            A :class:`KnucklesAPI` for the configured server.

        Raises:
            CliError: ``NOT_LOGGED_IN`` if no server is configured.
        """
        profile = resolve_profile(path=self.config, name=self.profile, env=self.env)
        return KnucklesAPI(profile.url, admin_token=profile.admin_token)


@dataclass
class Result:
    """What a command hands back for printing.

    Attributes:
        data: JSON payload for ``--json`` output.
        lines: Human-readable output lines.
        exit_code: Process exit status.
    """

    data: Any
    lines: list[str]
    exit_code: int = 0


def _read_secret(
    *, file: str | None, env_var: str, label: str, env: Mapping[str, str]
) -> str:
    """Read a secret without ever taking it from argv.

    Order: ``--*-file`` (``-`` means stdin), then the env var, then a
    hidden prompt when stdin is a terminal.

    Args:
        file: Path given on the command line, or ``None``.
        env_var: Environment variable to fall back to.
        label: Human name of the secret for prompts and errors.
        env: Process environment.

    Returns:
        The secret, whitespace-trimmed.

    Raises:
        CliError: ``INVALID_INPUT`` if no source supplies a value.
    """
    if file == "-":
        value = sys.stdin.read()
    elif file:
        value = Path(file).read_text()
    elif env.get(env_var):
        value = env[env_var]
    elif sys.stdin.isatty():
        value = getpass.getpass(f"{label}: ")
    else:
        raise CliError(
            INVALID_INPUT,
            f"No {label} given. Pass it with a --*-file option (use - for "
            f"stdin) or set {env_var}.",
        )
    value = value.strip()
    if not value:
        raise CliError(INVALID_INPUT, f"{label} is empty.")
    return value


def _row_lines(row: Mapping[str, Any]) -> list[str]:
    """Render a redacted app-client row as ``key: value`` lines.

    Args:
        row: The row.

    Returns:
        One line per field.
    """
    lines = []
    for key, value in row.items():
        shown = ", ".join(value) if isinstance(value, list) else value
        lines.append(f"{key}: {shown if shown not in (None, '') else '-'}")
    return lines


def _credentials_to_env(
    path: Path, *, url: str, client_id: str, secret: str, force: bool
) -> None:
    """Write the three consuming-app variables into a ``.env`` file.

    Args:
        path: The ``.env`` file.
        url: Knuckles base URL.
        client_id: Tenant ``client_id``.
        secret: Plaintext client secret.
        force: Overwrite differing values.
    """
    write_env(
        path,
        {
            "KNUCKLES_URL": url,
            "KNUCKLES_CLIENT_ID": client_id,
            "KNUCKLES_CLIENT_SECRET": secret,
        },
        force=force,
    )


# ---------------------------------------------------------------- login


def cmd_login(args: argparse.Namespace, ctx: Context) -> Result:
    """Verify an admin token against a server, then store the profile.

    Args:
        args: Parsed arguments (``url``, ``token_file``).
        ctx: Invocation context.

    Returns:
        The stored profile summary.
    """
    url = normalize_url(args.url)
    token = _read_secret(
        file=args.token_file,
        env_var="KNUCKLES_ADMIN_TOKEN",
        label="admin token",
        env=ctx.env,
    )
    apps = KnucklesAPI(url, admin_token=token).list_apps()
    save_profile(ctx.config, ctx.profile, Profile(url=url, admin_token=token))
    return Result(
        {"profile": ctx.profile, "url": url, "app_clients": len(apps)},
        [f"Logged in to {url} as profile {ctx.profile!r} ({len(apps)} app clients)."],
    )


def cmd_logout(args: argparse.Namespace, ctx: Context) -> Result:
    """Forget a stored profile.

    Args:
        args: Parsed arguments (unused).
        ctx: Invocation context.

    Returns:
        Whether a profile was removed.
    """
    removed = remove_profile(ctx.config, ctx.profile)
    message = "Logged out." if removed else f"No profile {ctx.profile!r} stored."
    return Result({"profile": ctx.profile, "removed": removed}, [message])


# ----------------------------------------------------------------- apps


def _create(args: argparse.Namespace, ctx: Context) -> tuple[dict[str, Any], str]:
    """Create a tenant, optionally writing its credentials to ``.env``.

    The ``.env`` file is checked for conflicts before the tenant is
    created, so a refusal leaves the server untouched.

    Args:
        args: Parsed arguments (``client_id``, ``name``, ``origin``,
            ``env_file``, ``force``).
        ctx: Invocation context.

    Returns:
        Tuple of the output payload and the server URL.
    """
    api = ctx.api()
    env_file = Path(args.env_file) if args.env_file else None
    origins = [origin_of(o) for o in args.origin]
    if env_file:
        check_env(
            env_file,
            {
                "KNUCKLES_URL": api.base_url,
                "KNUCKLES_CLIENT_ID": args.client_id,
                "KNUCKLES_CLIENT_SECRET": None,
            },
            force=args.force,
        )
    created = api.create_app(
        client_id=args.client_id, app_name=args.name, allowed_origins=origins
    )
    if env_file:
        secret = str(created.pop("client_secret"))
        _credentials_to_env(
            env_file,
            url=api.base_url,
            client_id=args.client_id,
            secret=secret,
            force=args.force,
        )
        created["env_file"] = str(env_file)
    return created, api.base_url


def cmd_apps_create(args: argparse.Namespace, ctx: Context) -> Result:
    """Register a tenant.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The created row (with the one-time secret unless written to a
        ``.env`` file).
    """
    data, _ = _create(args, ctx)
    lines = [f"Created {data['client_id']}."]
    if "client_secret" in data:
        lines.append(f"client_secret: {data['client_secret']}")
        lines.append("Store it now; it is never shown again.")
    else:
        lines.append(f"Credentials written to {data['env_file']}.")
    return Result(data, lines)


def cmd_init(args: argparse.Namespace, ctx: Context) -> Result:
    """Create a tenant and print the remaining setup steps.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The created row plus ``next_steps``.
    """
    data, _ = _create(args, ctx)
    cid = data["client_id"]
    origin = data["allowed_origins"][0] if data["allowed_origins"] else "<origin>"
    data["next_steps"] = [
        f"knuckles providers email {cid} --from 'Your App <signin@your-domain>'",
        f"knuckles providers google {cid} --client-secret-json client_secret.json",
        f"knuckles providers apple {cid} --services-id com.example.web "
        "--team-id TEAMID --p8 AuthKey_KEYID.p8",
        f"knuckles providers passkey {cid} --origin {origin}",
        f"knuckles doctor {cid}",
        "pip install knuckles-client   # or: npm install @knuckles/client",
    ]
    lines = [f"Created {cid}."]
    if "client_secret" in data:
        lines += [f"client_secret: {data['client_secret']}", "Store it now."]
    else:
        lines.append(f"Credentials written to {data['env_file']}.")
    lines += ["", "Next steps:"] + [f"  {step}" for step in data["next_steps"]]
    return Result(data, lines)


def cmd_apps_list(args: argparse.Namespace, ctx: Context) -> Result:
    """List tenants.

    Args:
        args: Parsed arguments (unused).
        ctx: Invocation context.

    Returns:
        Every redacted row.
    """
    apps = ctx.api().list_apps()
    lines = [
        f"{a['client_id']}\t{a['app_name']}\t{', '.join(a['allowed_origins'])}"
        for a in apps
    ] or ["No app clients."]
    return Result(apps, lines)


def cmd_apps_show(args: argparse.Namespace, ctx: Context) -> Result:
    """Show one tenant.

    Args:
        args: Parsed arguments (``client_id``).
        ctx: Invocation context.

    Returns:
        The redacted row.
    """
    row = ctx.api().get_app(args.client_id)
    return Result(row, _row_lines(row))


def cmd_apps_rotate(args: argparse.Namespace, ctx: Context) -> Result:
    """Rotate a tenant's client secret.

    Args:
        args: Parsed arguments (``client_id``, ``env_file``, ``force``).
        ctx: Invocation context.

    Returns:
        The new secret, unless written to a ``.env`` file.
    """
    api = ctx.api()
    env_file = Path(args.env_file) if args.env_file else None
    if env_file:
        check_env(env_file, {"KNUCKLES_CLIENT_SECRET": None}, force=args.force)
    data = api.rotate_secret(args.client_id)
    if env_file:
        write_env(
            env_file,
            {"KNUCKLES_CLIENT_SECRET": str(data.pop("client_secret"))},
            force=True,
        )
        data["env_file"] = str(env_file)
        return Result(data, [f"New secret written to {env_file}."])
    return Result(
        data,
        [
            f"client_secret: {data['client_secret']}",
            "The old secret stops working now.",
        ],
    )


def cmd_apps_origins(args: argparse.Namespace, ctx: Context) -> Result:
    """Replace a tenant's allowed origins.

    Args:
        args: Parsed arguments (``client_id``, ``origins``).
        ctx: Invocation context.

    Returns:
        The updated row.
    """
    origins = [origin_of(o) for o in args.origins]
    row = ctx.api().set_origins(args.client_id, origins)
    return Result(row, [f"Allowed origins: {', '.join(origins)}"])


# ------------------------------------------------------------ providers


def _patched(row: dict[str, Any], what: str, warnings: list[str]) -> Result:
    """Build the result for a provider update.

    Args:
        row: Updated redacted row.
        what: Name of what was configured.
        warnings: Non-fatal problems to surface.

    Returns:
        A result carrying the row and warnings.
    """
    lines = [f"{what} configured for {row.get('client_id')}."]
    lines += [f"warning: {w}" for w in warnings]
    return Result({"app": row, "warnings": warnings}, lines)


def cmd_providers_google(args: argparse.Namespace, ctx: Context) -> Result:
    """Configure Google sign-in from the console's JSON or by hand.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The updated row and any redirect-origin warnings.
    """
    redirect_origins: list[str] = []
    if args.client_secret_json:
        creds = parse_google_client_secret(Path(args.client_secret_json).read_text())
        client_id, secret = creds.client_id, creds.client_secret
        redirect_origins = creds.redirect_origins
    else:
        client_id = args.client_id
        secret = _read_secret(
            file=args.client_secret_file,
            env_var="KNUCKLES_GOOGLE_CLIENT_SECRET",
            label="Google client secret",
            env=ctx.env,
        )
    api = ctx.api()
    allowed = {o.lower() for o in api.get_app(args.app)["allowed_origins"]}
    warnings = [
        f"Google redirect origin {o} is not an allowed origin of {args.app}; "
        "add it with `knuckles apps set-origins` or sign-in starts will be rejected."
        for o in redirect_origins
        if o not in allowed
    ]
    row = api.update_app(
        args.app,
        {"google_oauth_client_id": client_id, "google_oauth_client_secret": secret},
    )
    return _patched(row, "Google sign-in", warnings)


def cmd_providers_apple(args: argparse.Namespace, ctx: Context) -> Result:
    """Configure Sign in with Apple from the ``.p8`` key file.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The updated row.

    Raises:
        CliError: If the key id cannot be determined or any value is
            malformed.
    """
    pem = Path(args.p8).read_text()
    validate_apple_private_key(pem)
    key_id = args.key_id or apple_key_id_from_filename(args.p8)
    if not key_id:
        raise CliError(
            INVALID_INPUT,
            "Could not read the key id from the filename; pass --key-id.",
        )
    fields = {
        "apple_oauth_client_id": validate_services_id(args.services_id),
        "apple_oauth_team_id": validate_apple_identifier(args.team_id, "team id"),
        "apple_oauth_key_id": validate_apple_identifier(key_id, "key id"),
        "apple_oauth_private_key": pem,
    }
    row = ctx.api().update_app(args.app, fields)
    return _patched(row, "Sign in with Apple", [])


def cmd_providers_email(args: argparse.Namespace, ctx: Context) -> Result:
    """Configure magic-link email (Resend), checking the domain first.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The updated row and any verification warning.

    Raises:
        CliError: ``EMAIL_DOMAIN_UNVERIFIED`` when Resend reports the
            sending domain is missing or unverified.
    """
    domain = email_address_of(args.from_email).rsplit("@", 1)[1].lower()
    api_key = _read_secret(
        file=args.api_key_file,
        env_var="KNUCKLES_RESEND_API_KEY",
        label="Resend API key",
        env=ctx.env,
    )
    warnings: list[str] = []
    if not args.no_verify:
        status, detail = check_resend_domain(api_key, domain)
        if status == "fail":
            raise CliError(EMAIL_DOMAIN_UNVERIFIED, detail)
        if status == "warn":
            warnings.append(detail)
    row = ctx.api().update_app(
        args.app, {"resend_api_key": api_key, "resend_from_email": args.from_email}
    )
    return _patched(row, "Magic-link email", warnings)


def cmd_providers_passkey(args: argparse.Namespace, ctx: Context) -> Result:
    """Configure the WebAuthn relying party for passkeys.

    Args:
        args: Parsed arguments.
        ctx: Invocation context.

    Returns:
        The updated row.
    """
    api = ctx.api()
    rp_name = args.rp_name or str(api.get_app(args.app)["app_name"])
    fields: dict[str, Any] = passkey_config(
        origin=args.origin, rp_id=args.rp_id, rp_name=rp_name
    )
    fields["force_webauthn_rp_id"] = args.force_rp_id
    row = api.update_app(args.app, fields)
    return _patched(row, "Passkeys", [])


def cmd_providers_clear(args: argparse.Namespace, ctx: Context) -> Result:
    """Clear a config group back to the operator env fallback.

    Args:
        args: Parsed arguments (``app``, ``group``, ``force_rp_id``).
        ctx: Invocation context.

    Returns:
        The updated row.
    """
    group = CONFIG_GROUPS[args.group]
    fields: dict[str, Any] = dict.fromkeys(group.columns)
    if group.name == "passkey":
        fields["force_webauthn_rp_id"] = args.force_rp_id
    row = ctx.api().update_app(args.app, fields)
    return Result({"app": row}, [f"Cleared {group.name} for {args.app}."])


# --------------------------------------------------------------- doctor

_MARKS = {"ok": "✓", "warn": "!", "fail": "✗"}


def cmd_doctor(args: argparse.Namespace, ctx: Context) -> Result:
    """Check the server and its tenants.

    Args:
        args: Parsed arguments (optional ``client_id``).
        ctx: Invocation context.

    Returns:
        Every check; exit code 1 if any failed.
    """
    api = ctx.api()
    checks = check_server(api)
    if not api.has_admin_token:
        checks.append(Check("admin", "warn", "No admin token; tenant checks skipped."))
    else:
        try:
            rows = [api.get_app(args.client_id)] if args.client_id else api.list_apps()
        except CliError as exc:
            checks.append(Check("admin", "fail", f"{exc.code}: {exc.message}"))
        else:
            for row in rows:
                checks.extend(check_app(row))

    counts = {s: sum(c.status == s for c in checks) for s in _MARKS}
    lines = [f"{_MARKS[c.status]} {c.name}: {c.detail}" for c in checks]
    lines.append(
        f"\n{counts['ok']} ok, {counts['warn']} warnings, {counts['fail']} failed"
    )
    return Result(
        {"checks": [c.to_dict() for c in checks], "summary": counts},
        lines,
        exit_code=1 if counts["fail"] else 0,
    )


# --------------------------------------------------------------- parser


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for every subcommand.

    Returns:
        The configured parser; each leaf sets ``handler``.
    """
    parser = argparse.ArgumentParser(
        prog="knuckles",
        description="Provision and check Knuckles identity tenants.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--json", action="store_true", help="Print JSON envelopes.")
    parser.add_argument(
        "--profile", help="Profile name (default: $KNUCKLES_PROFILE or 'default')."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="Store a server URL and admin token.")
    login.add_argument("--url", required=True, help="Knuckles base URL.")
    login.add_argument(
        "--token-file",
        help="File holding the admin token ('-' for stdin). Defaults to "
        "$KNUCKLES_ADMIN_TOKEN, then a hidden prompt.",
    )
    login.set_defaults(handler=cmd_login)

    logout = sub.add_parser("logout", help="Forget the stored profile.")
    logout.set_defaults(handler=cmd_logout)

    def add_create_args(p: argparse.ArgumentParser) -> None:
        """Add the shared tenant-creation arguments.

        Args:
            p: Parser to extend.
        """
        p.add_argument("client_id", help="New client id (lowercase slug).")
        p.add_argument("--name", required=True, help="Human-facing app name.")
        p.add_argument(
            "--origin",
            action="append",
            default=[],
            help="Allowed origin (repeatable), e.g. https://app.example.com.",
        )
        p.add_argument(
            "--env-file",
            help="Write KNUCKLES_URL/CLIENT_ID/CLIENT_SECRET into this .env file.",
        )
        p.add_argument(
            "--force", action="store_true", help="Overwrite differing .env values."
        )

    init = sub.add_parser("init", help="Create a tenant and print next steps.")
    add_create_args(init)
    init.set_defaults(handler=cmd_init)

    apps = sub.add_parser("apps", help="Manage app clients (tenants).")
    apps_sub = apps.add_subparsers(dest="apps_command", required=True)
    apps_sub.add_parser("list", help="List tenants.").set_defaults(
        handler=cmd_apps_list
    )
    show = apps_sub.add_parser("show", help="Show one tenant.")
    show.add_argument("client_id")
    show.set_defaults(handler=cmd_apps_show)
    create = apps_sub.add_parser("create", help="Register a tenant.")
    add_create_args(create)
    create.set_defaults(handler=cmd_apps_create)
    rotate = apps_sub.add_parser("rotate-secret", help="Mint a new client secret.")
    rotate.add_argument("client_id")
    rotate.add_argument("--env-file", help="Write the new secret into this .env.")
    rotate.add_argument(
        "--force", action="store_true", help="Overwrite an existing secret."
    )
    rotate.set_defaults(handler=cmd_apps_rotate)
    origins = apps_sub.add_parser("set-origins", help="Replace allowed origins.")
    origins.add_argument("client_id")
    origins.add_argument("origins", nargs="+")
    origins.set_defaults(handler=cmd_apps_origins)

    providers = sub.add_parser("providers", help="Configure sign-in methods.")
    prov_sub = providers.add_subparsers(dest="providers_command", required=True)

    google = prov_sub.add_parser("google", help="Sign in with Google.")
    google.add_argument("app", help="Tenant client id.")
    source = google.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--client-secret-json",
        help="The client_secret_*.json downloaded from Google Cloud Console.",
    )
    source.add_argument("--client-id", help="Google OAuth client id (manual entry).")
    google.add_argument(
        "--client-secret-file",
        help="With --client-id: file holding the secret ('-' for stdin). "
        "Defaults to $KNUCKLES_GOOGLE_CLIENT_SECRET, then a prompt.",
    )
    google.set_defaults(handler=cmd_providers_google)

    apple = prov_sub.add_parser("apple", help="Sign in with Apple.")
    apple.add_argument("app", help="Tenant client id.")
    apple.add_argument("--services-id", required=True, help="Apple Services ID.")
    apple.add_argument("--team-id", required=True, help="Apple Developer team id.")
    apple.add_argument("--p8", required=True, help="Path to AuthKey_<KEYID>.p8.")
    apple.add_argument("--key-id", help="Key id, if the .p8 was renamed.")
    apple.set_defaults(handler=cmd_providers_apple)

    email = prov_sub.add_parser("email", help="Magic-link email via Resend.")
    email.add_argument("app", help="Tenant client id.")
    email.add_argument(
        "--from",
        dest="from_email",
        required=True,
        help="From address, e.g. 'My App <signin@mail.example.com>'.",
    )
    email.add_argument(
        "--api-key-file",
        help="File holding the Resend API key ('-' for stdin). Defaults to "
        "$KNUCKLES_RESEND_API_KEY, then a prompt.",
    )
    email.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip the Resend domain-verification check.",
    )
    email.set_defaults(handler=cmd_providers_email)

    passkey = prov_sub.add_parser("passkey", help="WebAuthn passkeys.")
    passkey.add_argument("app", help="Tenant client id.")
    passkey.add_argument("--origin", required=True, help="Site origin.")
    passkey.add_argument("--rp-id", help="Relying-party id (default: origin host).")
    passkey.add_argument("--rp-name", help="Name in the prompt (default: app name).")
    passkey.add_argument(
        "--force-rp-id",
        action="store_true",
        help="Allow changing an rp_id that existing passkeys are bound to.",
    )
    passkey.set_defaults(handler=cmd_providers_passkey)

    clear = prov_sub.add_parser("clear", help="Reset a group to env fallback.")
    clear.add_argument("app", help="Tenant client id.")
    clear.add_argument("group", choices=sorted(CONFIG_GROUPS))
    clear.add_argument("--force-rp-id", action="store_true")
    clear.set_defaults(handler=cmd_providers_clear)

    doctor = sub.add_parser("doctor", help="Check the server and tenants.")
    doctor.add_argument("client_id", nargs="?", help="Check only this tenant.")
    doctor.set_defaults(handler=cmd_doctor)
    return parser


def _print_error(exc: CliError, *, as_json: bool) -> None:
    """Report a failure in the requested format.

    Args:
        exc: The error.
        as_json: Print the API error envelope to stdout instead of
            text to stderr.
    """
    if as_json:
        print(json.dumps({"error": {"code": exc.code, "message": exc.message}}))
    else:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: Arguments after the program name; defaults to
            ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    env = os.environ
    ctx = Context(
        as_json=args.json,
        profile=args.profile or env.get("KNUCKLES_PROFILE") or "default",
        config=config_path(env),
        env=env,
    )
    try:
        result: Result = args.handler(args, ctx)
    except CliError as exc:
        _print_error(exc, as_json=ctx.as_json)
        return 1
    except OSError as exc:
        _print_error(CliError(INVALID_INPUT, str(exc)), as_json=ctx.as_json)
        return 1

    if ctx.as_json:
        print(json.dumps({"data": result.data}, indent=2))
    else:
        print("\n".join(result.lines))
    return result.exit_code
