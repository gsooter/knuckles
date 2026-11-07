"""Shared fixtures for the knuckles-cli test suite."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from knuckles_cli.cli import main

BASE_URL = "https://auth.example.com"
ADMIN_TOKEN = "admin-secret-token"
APP_ORIGIN = "https://app.example.com"

RunResult = tuple[int, str, str]


def app_row(**overrides: Any) -> dict[str, Any]:
    """Build a redacted app-client row shaped like the admin API's.

    Args:
        **overrides: Fields to replace on the default row.

    Returns:
        A dict matching ``app_clients_service.serialize`` output.
    """
    row: dict[str, Any] = {
        "client_id": "my-site",
        "app_name": "My Site",
        "allowed_origins": [APP_ORIGIN],
        "created_at": "2026-11-07T00:00:00+00:00",
        "resend_from_email": None,
        "google_oauth_client_id": None,
        "apple_oauth_client_id": None,
        "apple_oauth_team_id": None,
        "apple_oauth_key_id": None,
        "webauthn_rp_id": None,
        "webauthn_rp_name": None,
        "webauthn_origin": None,
        "resend_api_key_configured": False,
        "google_oauth_client_secret_configured": False,
        "apple_oauth_private_key_configured": False,
    }
    row.update(overrides)
    return row


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI config at a temp file and clear Knuckles env vars.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        The config file path the CLI will use.
    """
    for var in (
        "KNUCKLES_URL",
        "KNUCKLES_ADMIN_TOKEN",
        "KNUCKLES_PROFILE",
        "KNUCKLES_RESEND_API_KEY",
        "KNUCKLES_GOOGLE_CLIENT_SECRET",
        "XDG_CONFIG_HOME",
    ):
        monkeypatch.delenv(var, raising=False)
    config = tmp_path / "config" / "config.json"
    monkeypatch.setenv("KNUCKLES_CONFIG", str(config))
    return config


@pytest.fixture()
def mocked() -> Iterator[responses.RequestsMock]:
    """Yield an active ``responses`` mock per test.

    Yields:
        An active :class:`responses.RequestsMock`.
    """
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture()
def run(capsys: pytest.CaptureFixture[str]) -> Callable[..., RunResult]:
    """Return a helper that runs the CLI and captures its output.

    Args:
        capsys: Pytest capture fixture.

    Returns:
        A callable taking argv strings and returning
        ``(exit_code, stdout, stderr)``.
    """

    def _run(*argv: str) -> RunResult:
        """Invoke ``knuckles`` with the given arguments.

        Args:
            *argv: Command-line arguments after the program name.

        Returns:
            Tuple of exit code, captured stdout, captured stderr.
        """
        code = main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture()
def logged_in(isolated_env: Path) -> Path:
    """Write a default profile so commands have a server and token.

    Args:
        isolated_env: The temp config path.

    Returns:
        The config file path.
    """
    isolated_env.parent.mkdir(parents=True, exist_ok=True)
    isolated_env.write_text(
        json.dumps(
            {"profiles": {"default": {"url": BASE_URL, "admin_token": ADMIN_TOKEN}}}
        )
    )
    return isolated_env


@pytest.fixture()
def apple_p8(tmp_path: Path) -> Path:
    """Write a valid P-256 PKCS#8 key named like Apple's download.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path to ``AuthKey_ABCDE12345.p8``.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "AuthKey_ABCDE12345.p8"
    path.write_bytes(pem)
    return path


@pytest.fixture()
def rsa_pem() -> str:
    """Return an RSA private key PEM (the wrong key type for Apple).

    Returns:
        PEM text of a fresh RSA key.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture()
def google_json(tmp_path: Path) -> Path:
    """Write a Google Cloud ``client_secret_*.json`` web-client file.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path to the JSON file.
    """
    path = tmp_path / "client_secret_123.apps.googleusercontent.com.json"
    path.write_text(
        json.dumps(
            {
                "web": {
                    "client_id": "123.apps.googleusercontent.com",
                    "client_secret": "GOCSPX-test",
                    "redirect_uris": [f"{APP_ORIGIN}/auth/google/callback"],
                    "javascript_origins": [APP_ORIGIN],
                }
            }
        )
    )
    return path
