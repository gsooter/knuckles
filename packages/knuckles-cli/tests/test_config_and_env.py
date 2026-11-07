"""Tests for profile storage and consuming-app ``.env`` writing."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from knuckles_cli.config import (
    Profile,
    config_path,
    load_profiles,
    remove_profile,
    resolve_profile,
    save_profile,
)
from knuckles_cli.envfile import write_env
from knuckles_cli.errors import CliError

from .conftest import ADMIN_TOKEN, BASE_URL


class TestConfig:
    """Profile persistence and resolution."""

    def test_config_path_honours_override(self, isolated_env: Path) -> None:
        """``KNUCKLES_CONFIG`` wins over the XDG default."""
        assert config_path() == isolated_env

    def test_config_path_xdg_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without an override the file lives under XDG_CONFIG_HOME."""
        monkeypatch.delenv("KNUCKLES_CONFIG")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/xdg")
        assert config_path() == Path("/xdg/knuckles/config.json")

    def test_save_is_owner_only(self, isolated_env: Path) -> None:
        """The admin token is on disk, so the file must be 0600."""
        save_profile(isolated_env, "default", Profile(BASE_URL, ADMIN_TOKEN))
        mode = stat.S_IMODE(isolated_env.stat().st_mode)
        assert mode == 0o600
        assert load_profiles(isolated_env)["default"].admin_token == ADMIN_TOKEN

    def test_remove_profile(self, isolated_env: Path) -> None:
        """Removing reports whether a profile existed."""
        save_profile(isolated_env, "default", Profile(BASE_URL, ADMIN_TOKEN))
        assert remove_profile(isolated_env, "default") is True
        assert remove_profile(isolated_env, "default") is False

    def test_env_overrides_profile(self, isolated_env: Path) -> None:
        """KNUCKLES_URL / KNUCKLES_ADMIN_TOKEN beat the stored profile."""
        save_profile(isolated_env, "default", Profile(BASE_URL, ADMIN_TOKEN))
        profile = resolve_profile(
            path=isolated_env,
            name="default",
            env={
                "KNUCKLES_URL": "https://other.example.com/",
                "KNUCKLES_ADMIN_TOKEN": "t",
            },
        )
        assert profile == Profile("https://other.example.com", "t")

    def test_env_alone_is_enough(self, isolated_env: Path) -> None:
        """CI can run with env vars and no config file at all."""
        profile = resolve_profile(
            path=isolated_env, name="default", env={"KNUCKLES_URL": BASE_URL}
        )
        assert profile == Profile(BASE_URL, None)

    def test_nothing_configured_errors(self, isolated_env: Path) -> None:
        """No profile and no env var points the user at ``login``."""
        with pytest.raises(CliError) as exc:
            resolve_profile(path=isolated_env, name="default", env={})
        assert exc.value.code == "NOT_LOGGED_IN"

    def test_corrupt_config_errors(self, isolated_env: Path) -> None:
        """A hand-mangled config file fails loudly, not silently."""
        isolated_env.parent.mkdir(parents=True)
        isolated_env.write_text("{nope")
        with pytest.raises(CliError):
            load_profiles(isolated_env)


class TestEnvFile:
    """Writing credentials into a consuming app's ``.env``."""

    def test_creates_owner_only_file(self, tmp_path: Path) -> None:
        """A new file is created 0600 with the given keys."""
        path = tmp_path / ".env"
        write_env(path, {"KNUCKLES_CLIENT_ID": "my-site"})
        assert path.read_text() == "KNUCKLES_CLIENT_ID=my-site\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_updates_in_place_and_keeps_other_lines(self, tmp_path: Path) -> None:
        """Existing keys are replaced, unrelated lines untouched."""
        path = tmp_path / ".env"
        path.write_text("# app\nDATABASE_URL=x\nKNUCKLES_CLIENT_ID=my-site\n")
        write_env(path, {"KNUCKLES_CLIENT_ID": "my-site", "KNUCKLES_URL": BASE_URL})
        assert path.read_text() == (
            "# app\nDATABASE_URL=x\nKNUCKLES_CLIENT_ID=my-site\n"
            f"KNUCKLES_URL={BASE_URL}\n"
        )

    def test_refuses_to_clobber_different_value(self, tmp_path: Path) -> None:
        """Overwriting a different secret needs --force."""
        path = tmp_path / ".env"
        path.write_text("KNUCKLES_CLIENT_SECRET=old\n")
        with pytest.raises(CliError) as exc:
            write_env(path, {"KNUCKLES_CLIENT_SECRET": "new"})
        assert exc.value.code == "ENV_FILE_CONFLICT"
        assert path.read_text() == "KNUCKLES_CLIENT_SECRET=old\n"

    def test_force_overwrites(self, tmp_path: Path) -> None:
        """--force replaces a conflicting value."""
        path = tmp_path / ".env"
        path.write_text("KNUCKLES_CLIENT_SECRET=old\n")
        write_env(path, {"KNUCKLES_CLIENT_SECRET": "new"}, force=True)
        assert path.read_text() == "KNUCKLES_CLIENT_SECRET=new\n"
