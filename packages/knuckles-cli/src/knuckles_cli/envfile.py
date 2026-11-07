"""Write Knuckles credentials into a consuming app's ``.env`` file."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from knuckles_cli.errors import ENV_FILE_CONFLICT, CliError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _unquote(value: str) -> str:
    """Strip one layer of matching quotes from a dotenv value.

    Args:
        value: Raw right-hand side.

    Returns:
        The unquoted value.
    """
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def check_env(
    path: Path, values: Mapping[str, str | None], *, force: bool = False
) -> None:
    """Fail if writing ``values`` would clobber different existing ones.

    Callers run this before an irreversible step (creating a tenant,
    rotating a secret) so a conflict is caught while nothing has
    changed yet.

    Args:
        path: The ``.env`` file.
        values: Keys and values about to be written. A ``None`` value
            stands for one not known yet (a secret about to be minted),
            which conflicts with any existing non-empty value.
        force: Skip the check.

    Raises:
        CliError: ``ENV_FILE_CONFLICT`` naming the clashing keys.
    """
    if force or not path.exists():
        return
    clashes = []
    for line in path.read_text().splitlines():
        match = _ASSIGNMENT_RE.match(line)
        if not match:
            continue
        key, raw = match.groups()
        existing = _unquote(raw)
        if key in values and existing and existing != values[key]:
            clashes.append(key)
    if clashes:
        raise CliError(
            ENV_FILE_CONFLICT,
            f"{path} already sets {', '.join(clashes)} to a different value. "
            "Re-run with --force to overwrite.",
        )


def write_env(path: Path, values: dict[str, str], *, force: bool = False) -> None:
    """Set keys in a ``.env`` file, preserving every other line.

    Existing assignments are replaced in place; new keys are appended
    in the order given. A newly created file is mode 0600.

    Args:
        path: The ``.env`` file.
        values: Keys and values to set.
        force: Overwrite keys that already hold a different value.

    Raises:
        CliError: ``ENV_FILE_CONFLICT`` if a key holds a different
            value and ``force`` is false.
    """
    check_env(path, values, force=force)
    lines = path.read_text().splitlines() if path.exists() else []
    remaining = dict(values)
    output: list[str] = []
    for line in lines:
        match = _ASSIGNMENT_RE.match(line)
        if match and match.group(1) in remaining:
            key = match.group(1)
            output.append(f"{key}={remaining.pop(key)}")
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in remaining.items())

    path.parent.mkdir(parents=True, exist_ok=True)
    # The mode only applies on creation: an existing file keeps its own.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write("\n".join(output) + "\n")
