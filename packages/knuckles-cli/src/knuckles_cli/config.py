"""Operator profiles: which Knuckles server, and which admin token.

Profiles live in a JSON file (default
``$XDG_CONFIG_HOME/knuckles/config.json``, overridable with
``KNUCKLES_CONFIG``) written with mode 0600 because it holds the admin
token. ``KNUCKLES_URL`` and ``KNUCKLES_ADMIN_TOKEN`` override the
stored profile, so CI and agents can run with env vars and no file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from knuckles_cli.errors import INVALID_INPUT, NOT_LOGGED_IN, CliError

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class Profile:
    """One configured Knuckles server.

    Attributes:
        url: Knuckles base URL, no trailing slash.
        admin_token: Operator admin token, or ``None`` for public-only
            use (e.g. ``doctor`` against the discovery endpoints).
    """

    url: str
    admin_token: str | None


def normalize_url(url: str) -> str:
    """Validate a Knuckles base URL and strip any trailing slash.

    The URL must match the server's ``KNUCKLES_BASE_URL`` exactly (it
    is the JWT ``iss``), so the trailing slash is normalized away here.

    Args:
        url: The URL as typed.

    Returns:
        The URL without a trailing slash.

    Raises:
        CliError: If the URL is not absolute http(s).
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise CliError(INVALID_INPUT, f"Not an http(s) URL: {url!r}")
    return url.strip().rstrip("/")


def config_path(env: Mapping[str, str] | None = None) -> Path:
    """Return where the profile file lives.

    Args:
        env: Environment to read; defaults to ``os.environ``.

    Returns:
        ``KNUCKLES_CONFIG`` if set, else
        ``$XDG_CONFIG_HOME/knuckles/config.json`` (``~/.config`` when
        XDG is unset).
    """
    env = os.environ if env is None else env
    override = env.get("KNUCKLES_CONFIG")
    if override:
        return Path(override)
    base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "knuckles" / "config.json"


def _read_raw(path: Path) -> dict[str, Any]:
    """Read the config file as a dict, tolerating its absence.

    Args:
        path: Config file path.

    Returns:
        The parsed object, or ``{}`` when the file does not exist.

    Raises:
        CliError: If the file exists but is not a JSON object.
    """
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise CliError(INVALID_INPUT, f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CliError(INVALID_INPUT, f"{path} must contain a JSON object.")
    return raw


def _write_raw(path: Path, raw: dict[str, Any]) -> None:
    """Write the config file owner-only (0600).

    Args:
        path: Config file path.
        raw: Object to serialize.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(raw, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def load_profiles(path: Path) -> dict[str, Profile]:
    """Load every stored profile.

    Args:
        path: Config file path.

    Returns:
        Mapping of profile name to :class:`Profile`.

    Raises:
        CliError: If the file is malformed.
    """
    profiles = _read_raw(path).get("profiles", {})
    if not isinstance(profiles, dict):
        raise CliError(INVALID_INPUT, f"{path}: 'profiles' must be an object.")
    result: dict[str, Profile] = {}
    for name, value in profiles.items():
        if not isinstance(value, dict) or not isinstance(value.get("url"), str):
            raise CliError(INVALID_INPUT, f"{path}: profile {name!r} has no url.")
        token = value.get("admin_token")
        result[name] = Profile(
            url=value["url"], admin_token=token if isinstance(token, str) else None
        )
    return result


def save_profile(path: Path, name: str, profile: Profile) -> None:
    """Create or replace one profile, keeping the others.

    Args:
        path: Config file path.
        name: Profile name.
        profile: Values to store.
    """
    raw = _read_raw(path)
    profiles = raw.setdefault("profiles", {})
    profiles[name] = {"url": profile.url, "admin_token": profile.admin_token}
    _write_raw(path, raw)


def remove_profile(path: Path, name: str) -> bool:
    """Delete one profile.

    Args:
        path: Config file path.
        name: Profile name.

    Returns:
        ``True`` if the profile existed.
    """
    raw = _read_raw(path)
    profiles = raw.get("profiles", {})
    if name not in profiles:
        return False
    del profiles[name]
    _write_raw(path, raw)
    return True


def resolve_profile(*, path: Path, name: str, env: Mapping[str, str]) -> Profile:
    """Work out which server and token a command should use.

    Args:
        path: Config file path.
        name: Profile name to load.
        env: Environment whose ``KNUCKLES_URL`` / ``KNUCKLES_ADMIN_TOKEN``
            override the stored profile.

    Returns:
        The effective :class:`Profile`.

    Raises:
        CliError: ``NOT_LOGGED_IN`` when neither a stored profile nor
            ``KNUCKLES_URL`` names a server.
    """
    stored = load_profiles(path).get(name)
    url = env.get("KNUCKLES_URL") or (stored.url if stored else None)
    if not url:
        raise CliError(
            NOT_LOGGED_IN,
            f"No Knuckles server configured for profile {name!r}. Run "
            "`knuckles login --url https://auth.example.com` or set KNUCKLES_URL.",
        )
    token = env.get("KNUCKLES_ADMIN_TOKEN") or (stored.admin_token if stored else None)
    return Profile(url=normalize_url(url), admin_token=token)
