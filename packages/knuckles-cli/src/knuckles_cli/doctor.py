"""Setup checks behind ``knuckles doctor``.

Server checks use only the public discovery endpoints; tenant checks
read the redacted admin row, so encrypted values are seen only as
``*_configured`` booleans (Decision #025).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

from knuckles_cli.errors import CliError
from knuckles_cli.providers import (
    CONFIG_GROUPS,
    ConfigGroup,
    is_local_host,
    passkey_config,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from knuckles_cli.api import KnucklesAPI

Status = Literal["ok", "warn", "fail"]


@dataclass(frozen=True)
class Check:
    """One doctor finding.

    Attributes:
        name: Short check name, prefixed with the client id for
            tenant checks.
        status: ``ok``, ``warn`` or ``fail``.
        detail: What was found and, for problems, what to do.
    """

    name: str
    status: Status
    detail: str

    def to_dict(self) -> dict[str, str]:
        """Render as a JSON-safe dict.

        Returns:
            ``{"name", "status", "detail"}``.
        """
        return asdict(self)


def _is_secure(url: str) -> bool:
    """Whether a URL is https or a local-development host.

    Args:
        url: Absolute URL or origin.

    Returns:
        ``True`` if tokens sent to it are not exposed in transit.
    """
    parts = urlsplit(url)
    return parts.scheme == "https" or is_local_host(parts.hostname or "")


def check_server(api: KnucklesAPI) -> list[Check]:
    """Check a deployment's public surface.

    Args:
        api: Client for the deployment.

    Returns:
        Health, issuer, JWKS and HTTPS checks — or a single failing
        ``reachable`` check when the server cannot be reached.
    """
    try:
        health_status, health = api.get_public("/health")
    except CliError as exc:
        return [Check("reachable", "fail", exc.message)]

    checks: list[Check] = []
    if (
        health_status == 200
        and isinstance(health, dict)
        and health.get("status") == "ok"
    ):
        checks.append(Check("health", "ok", "Server and database are up."))
    else:
        checks.append(
            Check("health", "fail", f"/health returned HTTP {health_status}: {health}")
        )

    _, discovery = api.get_public("/.well-known/openid-configuration")
    issuer = discovery.get("issuer") if isinstance(discovery, dict) else None
    if issuer == api.base_url:
        checks.append(Check("issuer", "ok", f"Tokens are issued by {issuer}."))
    else:
        checks.append(
            Check(
                "issuer",
                "fail",
                f"Server reports issuer {issuer!r} but you connected to "
                f"{api.base_url!r}. Set KNUCKLES_BASE_URL on the server to the "
                "exact URL apps use (no trailing slash) or every token fails "
                "issuer verification.",
            )
        )

    _, jwks = api.get_public("/.well-known/jwks.json")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if (
        isinstance(keys, list)
        and keys
        and all(isinstance(k, dict) and k.get("kid") for k in keys)
    ):
        checks.append(Check("jwks", "ok", f"{len(keys)} signing key(s) published."))
    else:
        checks.append(
            Check("jwks", "fail", "JWKS has no usable keys; apps cannot verify tokens.")
        )

    if urlsplit(api.base_url).scheme == "https":
        checks.append(Check("https", "ok", "Served over HTTPS."))
    elif _is_secure(api.base_url):
        checks.append(Check("https", "ok", "Local development host."))
    else:
        checks.append(
            Check("https", "warn", "Plain HTTP exposes tokens in transit; use HTTPS.")
        )
    return checks


def _is_set(row: Mapping[str, Any], group: ConfigGroup, column: str) -> bool:
    """Whether one tenant-config column has a value.

    Args:
        row: Redacted app-client row.
        group: The column's group.
        column: Column name.

    Returns:
        ``True`` when the column is populated.
    """
    if column in group.secret_columns:
        return bool(row.get(f"{column}_configured"))
    return bool(row.get(column))


def _check_origins(prefix: str, origins: list[str]) -> Check:
    """Check a tenant's allowed origins.

    Args:
        prefix: Check-name prefix (the client id).
        origins: The tenant's ``allowed_origins``.

    Returns:
        The origins check.
    """
    name = f"{prefix}: origins"
    if not origins:
        return Check(
            name,
            "fail",
            "No allowed origins: every redirect_url will be rejected. Add one "
            "with `knuckles apps set-origins`.",
        )
    insecure = [o for o in origins if not _is_secure(o)]
    if insecure:
        return Check(name, "warn", f"Not HTTPS: {', '.join(insecure)}.")
    return Check(name, "ok", ", ".join(origins))


def _check_passkey_fit(prefix: str, row: Mapping[str, Any]) -> Check:
    """Check a fully configured passkey group for internal consistency.

    Args:
        prefix: Check-name prefix (the client id).
        row: Redacted app-client row.

    Returns:
        The passkey check.
    """
    name = f"{prefix}: passkey"
    origin = str(row["webauthn_origin"])
    try:
        passkey_config(
            origin=origin,
            rp_id=str(row["webauthn_rp_id"]),
            rp_name=str(row["webauthn_rp_name"]),
        )
    except CliError as exc:
        return Check(name, "fail", exc.message)
    allowed = [o.rstrip("/").lower() for o in row.get("allowed_origins") or []]
    if origin.rstrip("/").lower() not in allowed:
        return Check(
            name,
            "warn",
            f"Passkey origin {origin} is not one of the allowed origins.",
        )
    return Check(name, "ok", f"rp_id {row['webauthn_rp_id']} for {origin}.")


def check_app(row: Mapping[str, Any]) -> list[Check]:
    """Check one tenant's configuration.

    Args:
        row: Redacted app-client row from the admin API.

    Returns:
        An origins check plus one check per config group.
    """
    prefix = str(row.get("client_id"))
    checks = [_check_origins(prefix, list(row.get("allowed_origins") or []))]
    for group in CONFIG_GROUPS.values():
        name = f"{prefix}: {group.name}"
        missing = [c for c in group.columns if not _is_set(row, group, c)]
        if len(missing) == len(group.columns):
            checks.append(
                Check(
                    name,
                    "warn",
                    "Not configured. Uses the operator env vars while "
                    "KNUCKLES_ALLOW_ENV_TENANT_FALLBACK is on; otherwise this "
                    f"sign-in method is off. Set it with `knuckles providers "
                    f"{group.name} {prefix}`.",
                )
            )
        elif missing and group.atomic:
            checks.append(
                Check(
                    name,
                    "fail",
                    f"Partially configured (missing {', '.join(missing)}): sign-in "
                    "fails with TENANT_CONFIG_INCOMPLETE.",
                )
            )
        elif missing:
            checks.append(
                Check(
                    name,
                    "warn",
                    f"{', '.join(missing)} not set; inherited from operator env vars.",
                )
            )
        elif group.name == "passkey":
            checks.append(_check_passkey_fit(prefix, row))
        else:
            checks.append(Check(name, "ok", "Configured."))
    return checks
