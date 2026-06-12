"""Shared per-tenant configuration resolution (Decisions #017 / #020).

Every ceremony service resolves its provider credentials through
:func:`resolve_tenant_fields` so the rules live in exactly one place:

* A field set on the ``app_clients`` row wins over the operator env
  var of the same name.
* **Atomic groups** (Google OAuth, Apple OAuth, WebAuthn RP) must be
  all-tenant or all-env: a half-configured group raises
  ``TENANT_CONFIG_INCOMPLETE`` instead of silently mixing one
  tenant's client id with the operator's client secret — a guaranteed
  provider-side failure that would otherwise surface as an opaque
  auth error at sign-in time.
* When ``KNUCKLES_ALLOW_ENV_TENANT_FALLBACK`` is ``false`` the env
  fallback is retired entirely: every field must come from the tenant
  row. This is the enforceable end state Decision #017 promised.

Empty strings are treated as unset, matching the configure CLI's
convention that ``""`` means "revert to inherit."
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from knuckles.core.config import get_settings
from knuckles.core.exceptions import TENANT_CONFIG_INCOMPLETE, AppError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from knuckles.data.models.auth import AppClient


def _incomplete(group: str, missing: list[str], *, strict: bool) -> AppError:
    """Build the loud configuration error for a broken tenant group.

    Args:
        group: Human-readable group name (e.g. ``google_oauth``).
        missing: Column names with no usable tenant value.
        strict: Whether the failure came from the retired-fallback
            mode rather than a partial group.

    Returns:
        An :class:`AppError` with code ``TENANT_CONFIG_INCOMPLETE``
        and HTTP 500 — this is an operator problem, not a caller
        problem.
    """
    reason = (
        "env fallback is disabled (KNUCKLES_ALLOW_ENV_TENANT_FALLBACK=false)"
        if strict
        else "the group is partially configured and would mix tenant and "
        "operator credentials"
    )
    return AppError(
        code=TENANT_CONFIG_INCOMPLETE,
        message=(
            f"Tenant configuration for '{group}' is incomplete: "
            f"missing {', '.join(sorted(missing))} — {reason}. "
            "Populate the columns via scripts/configure_app_client.py."
        ),
        status_code=500,
    )


def resolve_tenant_fields(
    client: AppClient | None,
    *,
    group: str,
    fields: Mapping[str, str],
    atomic: bool = True,
) -> dict[str, str]:
    """Resolve a group of tenant-config fields with env fallback rules.

    Args:
        client: The calling tenant's ``app_clients`` row, or ``None``
            when no row matches (legacy callers).
        group: Name of the config group for error messages.
        fields: Mapping of ``app_clients`` column name to the
            operator-level env fallback value for that field.
        atomic: When ``True`` (default) the group must be all-tenant
            or all-env. ``False`` permits per-field mixing (Resend,
            where a tenant may override only its From address).

    Returns:
        Mapping of column name to the resolved value for this tenant.

    Raises:
        AppError: With code ``TENANT_CONFIG_INCOMPLETE`` (HTTP 500)
            when an atomic group is partially configured, or when the
            env fallback is disabled and any field is missing from
            the tenant row.
    """
    tenant_values: dict[str, str | None] = {
        name: (getattr(client, name) or None) if client is not None else None
        for name in fields
    }
    missing = [name for name, value in tenant_values.items() if value is None]

    if not get_settings().knuckles_allow_env_tenant_fallback:
        if missing:
            raise _incomplete(group, missing, strict=True)
    elif atomic and missing and len(missing) < len(fields):
        raise _incomplete(group, missing, strict=False)

    return {name: tenant_values[name] or fields[name] for name in fields}
