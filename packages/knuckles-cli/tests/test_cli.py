"""End-to-end tests for the ``knuckles`` command surface."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest
import responses

from knuckles_cli.providers import RESEND_DOMAINS_URL

from .conftest import ADMIN_TOKEN, APP_ORIGIN, BASE_URL, RunResult, app_row

ADMIN = f"{BASE_URL}/v1/admin/app-clients"
Run = Callable[..., RunResult]


def _patched_fields(mocked: responses.RequestsMock) -> dict[str, object]:
    """Return the JSON body of the single PATCH the CLI sent.

    Args:
        mocked: Active ``responses`` mock.

    Returns:
        The decoded PATCH body.
    """
    patches = [c for c in mocked.calls if c.request.method == "PATCH"]
    assert len(patches) == 1
    body = patches[0].request.body
    assert body is not None
    return dict(json.loads(body))


class TestLogin:
    """``knuckles login`` / ``logout``."""

    def test_login_verifies_and_saves(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A working token is checked against the server, then stored."""
        monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", ADMIN_TOKEN)
        mocked.get(ADMIN, json={"data": [app_row()]})
        code, out, _ = run("--json", "login", "--url", f"{BASE_URL}/")
        assert code == 0
        assert json.loads(out)["data"] == {
            "profile": "default",
            "url": BASE_URL,
            "app_clients": 1,
        }
        assert mocked.calls[0].request.headers["X-Admin-Token"] == ADMIN_TOKEN
        stored = json.loads(isolated_env.read_text())
        assert stored["profiles"]["default"]["admin_token"] == ADMIN_TOKEN

    def test_login_reads_token_from_stdin(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--token-file -`` reads the token from stdin, not argv."""
        monkeypatch.setattr("sys.stdin", io.StringIO(f"{ADMIN_TOKEN}\n"))
        mocked.get(ADMIN, json={"data": []})
        code, _, _ = run("login", "--url", BASE_URL, "--token-file", "-")
        assert code == 0
        assert mocked.calls[0].request.headers["X-Admin-Token"] == ADMIN_TOKEN

    def test_bad_token_is_not_saved(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        isolated_env: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A rejected token surfaces the server code and stores nothing."""
        monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", "wrong")
        mocked.get(
            ADMIN,
            status=401,
            json={"error": {"code": "UNAUTHORIZED", "message": "Invalid admin token."}},
        )
        code, out, _ = run("--json", "login", "--url", BASE_URL)
        assert code == 1
        assert json.loads(out)["error"]["code"] == "UNAUTHORIZED"
        assert not isolated_env.exists()

    def test_disabled_admin_api_is_explained(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 404 NOT_FOUND on admin routes means KNUCKLES_ADMIN_TOKEN is unset."""
        monkeypatch.setenv("KNUCKLES_ADMIN_TOKEN", ADMIN_TOKEN)
        mocked.get(
            ADMIN,
            status=404,
            json={"error": {"code": "NOT_FOUND", "message": "Not found."}},
        )
        code, _, err = run("login", "--url", BASE_URL)
        assert code == 1
        assert "ADMIN_API_DISABLED" in err
        assert "KNUCKLES_ADMIN_TOKEN" in err

    def test_logout_removes_profile(self, run: Run, logged_in: Path) -> None:
        """``logout`` deletes the stored profile."""
        code, _, _ = run("logout")
        assert code == 0
        assert json.loads(logged_in.read_text())["profiles"] == {}


class TestApps:
    """``knuckles apps ...`` and ``init``."""

    def test_not_logged_in(self, run: Run) -> None:
        """Commands needing a server explain how to configure one."""
        code, out, _ = run("--json", "apps", "list")
        assert code == 1
        assert json.loads(out)["error"]["code"] == "NOT_LOGGED_IN"

    def test_list_human(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Human output names each tenant."""
        mocked.get(ADMIN, json={"data": [app_row()]})
        code, out, _ = run("apps", "list")
        assert code == 0
        assert "my-site" in out
        assert "My Site" in out

    def test_show_missing_app(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Server error codes pass through verbatim."""
        mocked.get(
            f"{ADMIN}/nope",
            status=404,
            json={"error": {"code": "APP_CLIENT_NOT_FOUND", "message": "No app."}},
        )
        code, out, _ = run("--json", "apps", "show", "nope")
        assert code == 1
        assert json.loads(out)["error"]["code"] == "APP_CLIENT_NOT_FOUND"

    def test_create_prints_secret_once(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Without --env-file the one-time secret goes to stdout."""
        mocked.post(
            ADMIN, status=201, json={"data": {**app_row(), "client_secret": "s3"}}
        )
        code, out, _ = run(
            "--json",
            "apps",
            "create",
            "my-site",
            "--name",
            "My Site",
            "--origin",
            APP_ORIGIN,
        )
        assert code == 0
        assert json.loads(out)["data"]["client_secret"] == "s3"
        sent = json.loads(mocked.calls[0].request.body or "{}")
        assert sent == {
            "client_id": "my-site",
            "app_name": "My Site",
            "allowed_origins": [APP_ORIGIN],
        }

    def test_init_writes_env_and_hides_secret(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        tmp_path: Path,
    ) -> None:
        """``init --env-file`` writes credentials and keeps them off stdout."""
        mocked.post(
            ADMIN, status=201, json={"data": {**app_row(), "client_secret": "s3"}}
        )
        env = tmp_path / ".env"
        code, out, _ = run(
            "--json",
            "init",
            "my-site",
            "--name",
            "My Site",
            "--origin",
            APP_ORIGIN,
            "--env-file",
            str(env),
        )
        assert code == 0
        data = json.loads(out)["data"]
        assert "client_secret" not in data
        assert data["env_file"] == str(env)
        assert data["next_steps"]
        assert env.read_text() == (
            f"KNUCKLES_URL={BASE_URL}\nKNUCKLES_CLIENT_ID=my-site\n"
            "KNUCKLES_CLIENT_SECRET=s3\n"
        )

    def test_init_refuses_conflicting_env_before_creating(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        tmp_path: Path,
    ) -> None:
        """A conflicting .env is caught before the tenant is created."""
        env = tmp_path / ".env"
        env.write_text("KNUCKLES_CLIENT_ID=someone-else\n")
        code, _, err = run(
            "init",
            "my-site",
            "--name",
            "My Site",
            "--origin",
            APP_ORIGIN,
            "--env-file",
            str(env),
        )
        assert code == 1
        assert "ENV_FILE_CONFLICT" in err
        assert not mocked.calls

    def test_rotate_secret_to_env(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        tmp_path: Path,
    ) -> None:
        """Rotation can write straight into the app's .env with --force."""
        env = tmp_path / ".env"
        env.write_text("KNUCKLES_CLIENT_SECRET=old\n")
        mocked.post(
            f"{ADMIN}/my-site/rotate-secret",
            json={"data": {"client_id": "my-site", "client_secret": "new"}},
        )
        code, _, _ = run(
            "apps", "rotate-secret", "my-site", "--env-file", str(env), "--force"
        )
        assert code == 0
        assert env.read_text() == "KNUCKLES_CLIENT_SECRET=new\n"

    def test_set_origins(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Origins are replaced wholesale."""
        mocked.put(f"{ADMIN}/my-site/origins", json={"data": app_row()})
        code, _, _ = run(
            "apps", "set-origins", "my-site", APP_ORIGIN, "http://localhost:3000"
        )
        assert code == 0
        sent = json.loads(mocked.calls[0].request.body or "{}")
        assert sent == {"allowed_origins": [APP_ORIGIN, "http://localhost:3000"]}


class TestProviders:
    """``knuckles providers ...``."""

    def test_google_from_downloaded_json(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        google_json: Path,
    ) -> None:
        """The console's JSON file configures the whole Google group."""
        mocked.get(f"{ADMIN}/my-site", json={"data": app_row()})
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, out, _ = run(
            "--json",
            "providers",
            "google",
            "my-site",
            "--client-secret-json",
            str(google_json),
        )
        assert code == 0
        assert _patched_fields(mocked) == {
            "google_oauth_client_id": "123.apps.googleusercontent.com",
            "google_oauth_client_secret": "GOCSPX-test",
        }
        assert json.loads(out)["data"]["warnings"] == []

    def test_google_warns_on_unknown_redirect_origin(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        google_json: Path,
    ) -> None:
        """Redirect URIs outside allowed_origins would be rejected at start."""
        mocked.get(
            f"{ADMIN}/my-site",
            json={"data": app_row(allowed_origins=["https://elsewhere.com"])},
        )
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, out, _ = run(
            "--json",
            "providers",
            "google",
            "my-site",
            "--client-secret-json",
            str(google_json),
        )
        assert code == 0
        assert APP_ORIGIN in json.loads(out)["data"]["warnings"][0]

    def test_google_manual_secret_from_env(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without the JSON file, the secret comes from env, never argv."""
        monkeypatch.setenv("KNUCKLES_GOOGLE_CLIENT_SECRET", "GOCSPX-env")
        mocked.get(f"{ADMIN}/my-site", json={"data": app_row()})
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, _, _ = run("providers", "google", "my-site", "--client-id", "abc")
        assert code == 0
        assert _patched_fields(mocked)["google_oauth_client_secret"] == "GOCSPX-env"

    def test_apple_from_p8(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        apple_p8: Path,
    ) -> None:
        """The key id is read from Apple's filename; the PEM is uploaded."""
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, _, _ = run(
            "providers",
            "apple",
            "my-site",
            "--services-id",
            "com.example.web",
            "--team-id",
            "ab12cd34ef",
            "--p8",
            str(apple_p8),
        )
        assert code == 0
        fields = _patched_fields(mocked)
        assert fields["apple_oauth_key_id"] == "ABCDE12345"
        assert fields["apple_oauth_team_id"] == "AB12CD34EF"
        assert fields["apple_oauth_client_id"] == "com.example.web"
        assert str(fields["apple_oauth_private_key"]).startswith(
            "-----BEGIN PRIVATE KEY"
        )

    def test_apple_bad_key_never_uploads(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        tmp_path: Path,
    ) -> None:
        """Local validation fails before any network call."""
        bad = tmp_path / "AuthKey_ABCDE12345.p8"
        bad.write_text("nope")
        code, _, _ = run(
            "providers",
            "apple",
            "my-site",
            "--services-id",
            "com.example.web",
            "--team-id",
            "AB12CD34EF",
            "--p8",
            str(bad),
        )
        assert code == 1
        assert not mocked.calls

    def test_email_verifies_domain_then_uploads(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The key from stdin is checked against Resend, then stored."""
        monkeypatch.setattr("sys.stdin", io.StringIO("re_live\n"))
        mocked.get(
            RESEND_DOMAINS_URL,
            json={"data": [{"name": "mail.example.com", "status": "verified"}]},
        )
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, _, _ = run(
            "providers",
            "email",
            "my-site",
            "--from",
            "Site <hi@mail.example.com>",
            "--api-key-file",
            "-",
        )
        assert code == 0
        assert _patched_fields(mocked) == {
            "resend_api_key": "re_live",
            "resend_from_email": "Site <hi@mail.example.com>",
        }

    def test_email_unverified_domain_blocks_upload(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        logged_in: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unverified sending domain stops before storing anything."""
        monkeypatch.setenv("KNUCKLES_RESEND_API_KEY", "re_live")
        mocked.get(RESEND_DOMAINS_URL, json={"data": []})
        code, _, err = run(
            "providers", "email", "my-site", "--from", "hi@mail.example.com"
        )
        assert code == 1
        assert "mail.example.com" in err
        assert not [c for c in mocked.calls if c.request.method == "PATCH"]

    def test_passkey_defaults_name_from_app(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """rp_name defaults to the tenant's app_name."""
        mocked.get(f"{ADMIN}/my-site", json={"data": app_row()})
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, _, _ = run("providers", "passkey", "my-site", "--origin", APP_ORIGIN)
        assert code == 0
        assert _patched_fields(mocked) == {
            "webauthn_origin": APP_ORIGIN,
            "webauthn_rp_id": "app.example.com",
            "webauthn_rp_name": "My Site",
            "force_webauthn_rp_id": False,
        }

    def test_clear_group(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Clearing nulls every column of the group."""
        mocked.patch(f"{ADMIN}/my-site", json={"data": app_row()})
        code, _, _ = run("providers", "clear", "my-site", "google")
        assert code == 0
        assert _patched_fields(mocked) == {
            "google_oauth_client_id": None,
            "google_oauth_client_secret": None,
        }


class TestDoctor:
    """``knuckles doctor`` exit codes and output."""

    def _mock_public(self, mocked: responses.RequestsMock) -> None:
        """Register healthy discovery endpoints.

        Args:
            mocked: Active ``responses`` mock.
        """
        mocked.get(f"{BASE_URL}/health", json={"status": "ok"})
        mocked.get(
            f"{BASE_URL}/.well-known/openid-configuration",
            json={"issuer": BASE_URL, "jwks_uri": f"{BASE_URL}/.well-known/jwks.json"},
        )
        mocked.get(
            f"{BASE_URL}/.well-known/jwks.json",
            json={"keys": [{"kid": "k1", "alg": "RS256", "kty": "RSA"}]},
        )

    def test_warnings_only_exit_zero(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """Unconfigured groups warn but don't fail the run."""
        self._mock_public(mocked)
        mocked.get(ADMIN, json={"data": [app_row()]})
        code, out, _ = run("doctor")
        assert code == 0
        assert "my-site: google" in out

    def test_failure_exits_one(
        self, run: Run, mocked: responses.RequestsMock, logged_in: Path
    ) -> None:
        """A partial atomic group fails the run for CI and agents."""
        self._mock_public(mocked)
        mocked.get(
            f"{ADMIN}/my-site", json={"data": app_row(google_oauth_client_id="g")}
        )
        code, out, _ = run("--json", "doctor", "my-site")
        assert code == 1
        checks = json.loads(out)["data"]["checks"]
        assert any(c["status"] == "fail" for c in checks)

    def test_server_only_without_token(
        self,
        run: Run,
        mocked: responses.RequestsMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With just KNUCKLES_URL, doctor checks the public surface."""
        monkeypatch.setenv("KNUCKLES_URL", BASE_URL)
        self._mock_public(mocked)
        code, out, _ = run("--json", "doctor")
        assert code == 0
        names = [c["name"] for c in json.loads(out)["data"]["checks"]]
        assert "admin" in names
