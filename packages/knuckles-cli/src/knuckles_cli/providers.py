"""Local parsing and validation of sign-in provider credentials.

Everything here runs before anything is uploaded, so a wrong file or a
typo fails on the operator's machine with a specific message instead of
as an opaque provider error at a user's first sign-in.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from knuckles_cli.errors import INVALID_INPUT, CliError

RESEND_DOMAINS_URL = "https://api.resend.com/domains"

_APPLE_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
_APPLE_KEY_FILENAME_RE = re.compile(r"^AuthKey_([A-Z0-9]{10})\.p8$")
_SERVICES_ID_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def is_local_host(host: str) -> bool:
    """Whether a hostname is a local-development host.

    Args:
        host: Bare hostname, no port.

    Returns:
        ``True`` for localhost, loopback addresses, and ``*.localhost``.
    """
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def origin_of(url: str) -> str:
    """Reduce a URL to its ``scheme://host[:port]`` origin.

    Args:
        url: Any absolute URL.

    Returns:
        The lowercase origin.

    Raises:
        CliError: If the URL is not absolute http(s).
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise CliError(INVALID_INPUT, f"Not an http(s) URL: {url!r}")
    return f"{parts.scheme}://{parts.netloc}".lower()


@dataclass(frozen=True)
class GoogleCredentials:
    """The useful parts of Google's ``client_secret_*.json``.

    Attributes:
        client_id: OAuth client id.
        client_secret: OAuth client secret.
        redirect_uris: Authorized redirect URIs from the console.
    """

    client_id: str
    client_secret: str
    redirect_uris: list[str] = field(default_factory=list)

    @property
    def redirect_origins(self) -> list[str]:
        """Distinct origins of the authorized redirect URIs.

        Returns:
            Origins in first-seen order.
        """
        origins: list[str] = []
        for uri in self.redirect_uris:
            origin = origin_of(uri)
            if origin not in origins:
                origins.append(origin)
        return origins


def parse_google_client_secret(text: str) -> GoogleCredentials:
    """Parse the JSON file Google Cloud Console downloads for a client.

    Args:
        text: File contents.

    Returns:
        The parsed credentials.

    Raises:
        CliError: If the file is not JSON, is not a "Web application"
            client, or lacks the id or secret.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliError(INVALID_INPUT, f"Google client file is not JSON: {exc}") from exc
    web = raw.get("web") if isinstance(raw, dict) else None
    if not isinstance(web, dict):
        raise CliError(
            INVALID_INPUT,
            "Google client file has no 'web' block. Create the OAuth client "
            "with application type 'Web application' and download it again.",
        )
    client_id = web.get("client_id")
    client_secret = web.get("client_secret")
    if not isinstance(client_id, str) or not isinstance(client_secret, str):
        raise CliError(
            INVALID_INPUT, "Google client file is missing client_id or client_secret."
        )
    uris = web.get("redirect_uris") or []
    return GoogleCredentials(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=[u for u in uris if isinstance(u, str)],
    )


def validate_apple_private_key(pem: str) -> None:
    """Check that a ``.p8`` file is the P-256 key Apple issues.

    Args:
        pem: PEM text of the key.

    Raises:
        CliError: If the text is not a PEM private key or is not on
            the P-256 curve (Apple's client secret is ES256).
    """
    try:
        key = load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise CliError(INVALID_INPUT, f"Not a PEM private key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise CliError(
            INVALID_INPUT,
            "Apple Sign-in keys are P-256 EC keys. Download the .p8 from "
            "Certificates, Identifiers & Profiles > Keys.",
        )


def apple_key_id_from_filename(path: str) -> str | None:
    """Read the key id out of Apple's ``AuthKey_<KEYID>.p8`` filename.

    Args:
        path: Path to the key file.

    Returns:
        The ten-character key id, or ``None`` if the file was renamed.
    """
    match = _APPLE_KEY_FILENAME_RE.match(Path(path).name)
    return match.group(1) if match else None


def validate_apple_identifier(value: str, name: str) -> str:
    """Normalize and check an Apple team id or key id.

    Args:
        value: The id as typed.
        name: Field name for the error message.

    Returns:
        The uppercase id.

    Raises:
        CliError: If it is not ten alphanumerics.
    """
    normalized = value.strip().upper()
    if not _APPLE_ID_RE.match(normalized):
        raise CliError(
            INVALID_INPUT, f"{name} must be 10 letters/digits, got {value!r}."
        )
    return normalized


def validate_services_id(value: str) -> str:
    """Check an Apple Services ID looks like reverse-DNS.

    Args:
        value: The Services ID as typed.

    Returns:
        The trimmed Services ID.

    Raises:
        CliError: If it is not dotted reverse-DNS.
    """
    trimmed = value.strip()
    if not _SERVICES_ID_RE.match(trimmed):
        raise CliError(
            INVALID_INPUT,
            f"Apple Services ID should look like com.example.web, got {value!r}.",
        )
    return trimmed


def passkey_config(
    *, origin: str, rp_name: str, rp_id: str | None = None
) -> dict[str, str]:
    """Derive the WebAuthn relying-party columns for a tenant.

    Args:
        origin: The site origin passkeys are used from.
        rp_name: Name shown in the browser's passkey prompt.
        rp_id: Optional relying-party id; defaults to the origin host.

    Returns:
        ``webauthn_origin`` / ``webauthn_rp_id`` / ``webauthn_rp_name``.

    Raises:
        CliError: If the origin is not a secure context or the rp_id
            is not the origin host or one of its parent domains.
    """
    normalized = origin_of(origin)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    if parts.scheme != "https" and not is_local_host(host):
        raise CliError(
            INVALID_INPUT,
            f"Passkeys need https (or localhost); {normalized} is not secure.",
        )
    effective_rp_id = (rp_id or host).strip().lower()
    if host != effective_rp_id and not host.endswith(f".{effective_rp_id}"):
        raise CliError(
            INVALID_INPUT,
            f"rp_id {effective_rp_id!r} must be {host!r} or a parent domain of it.",
        )
    return {
        "webauthn_origin": normalized,
        "webauthn_rp_id": effective_rp_id,
        "webauthn_rp_name": rp_name,
    }


def email_address_of(from_value: str) -> str:
    """Extract the bare address from a From value.

    Args:
        from_value: ``addr`` or ``Name <addr>``.

    Returns:
        The address.

    Raises:
        CliError: If no address is present.
    """
    _, address = parseaddr(from_value)
    if "@" not in address:
        raise CliError(INVALID_INPUT, f"No email address in {from_value!r}.")
    return address


def check_resend_domain(
    api_key: str, domain: str, *, timeout: float = 10.0
) -> tuple[str, str]:
    """Ask Resend whether a sending domain is verified for this key.

    Args:
        api_key: Resend API key.
        domain: The From address's domain.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of status (``ok`` / ``warn`` / ``fail``) and detail.
    """
    try:
        response = requests.get(
            RESEND_DOMAINS_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return "warn", f"Could not reach Resend to check {domain}: {exc}"
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not response.ok:
        name = str(body.get("name", "")) if isinstance(body, dict) else ""
        if name == "restricted_api_key":
            return "warn", (
                "This is a sending-only Resend key, so the domain could not be "
                f"checked. Confirm {domain} shows Verified at resend.com/domains."
            )
        message = body.get("message", "") if isinstance(body, dict) else ""
        return (
            "fail",
            f"Resend rejected the API key ({response.status_code}): {message}",
        )
    domains = body.get("data", []) if isinstance(body, dict) else []
    for entry in domains:
        if isinstance(entry, dict) and entry.get("name") == domain:
            status = entry.get("status")
            if status == "verified":
                return "ok", f"{domain} is verified in Resend."
            return "fail", (
                f"{domain} is {status} in Resend; add its DNS records and wait "
                "for verification."
            )
    return "fail", f"{domain} has not been added to this Resend account."


@dataclass(frozen=True)
class ConfigGroup:
    """One tenant-config group on ``app_clients`` (Decision #020).

    Attributes:
        name: CLI-facing group name.
        columns: Column names in the group.
        secret_columns: Columns the admin API exposes only as
            ``<column>_configured`` booleans.
        atomic: Whether a half-set group fails at sign-in time with
            ``TENANT_CONFIG_INCOMPLETE`` (non-atomic fields inherit the
            operator env var individually).
    """

    name: str
    columns: tuple[str, ...]
    secret_columns: frozenset[str]
    atomic: bool


CONFIG_GROUPS: dict[str, ConfigGroup] = {
    group.name: group
    for group in (
        ConfigGroup(
            "email",
            ("resend_api_key", "resend_from_email"),
            frozenset({"resend_api_key"}),
            atomic=False,
        ),
        ConfigGroup(
            "google",
            ("google_oauth_client_id", "google_oauth_client_secret"),
            frozenset({"google_oauth_client_secret"}),
            atomic=True,
        ),
        ConfigGroup(
            "apple",
            (
                "apple_oauth_client_id",
                "apple_oauth_team_id",
                "apple_oauth_key_id",
                "apple_oauth_private_key",
            ),
            frozenset({"apple_oauth_private_key"}),
            atomic=True,
        ),
        ConfigGroup(
            "passkey",
            ("webauthn_rp_id", "webauthn_rp_name", "webauthn_origin"),
            frozenset(),
            atomic=True,
        ),
    )
}
