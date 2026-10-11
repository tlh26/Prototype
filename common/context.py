"""
Runtime tenant context management.

ContextVar is used to represent the logical tenant scope
for the current execution context.

This is a runtime mechanism and is not itself part of the
forensic evidence model.
"""

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Generator, Optional

from evidence.tenant import TenantContext

_current_tenant: ContextVar[Optional[TenantContext]] = ContextVar(
    "current_tenant",
    default=None,
)


def get_current_tenant() -> TenantContext:
    """
    Return the TenantContext associated with the current
    execution context.

    Raises:
        RuntimeError:
            If no tenant context has been established.
    """

    tenant = _current_tenant.get()

    if tenant is None:
        raise RuntimeError("No tenant context is active.")

    return tenant


def set_current_tenant(
    tenant: TenantContext,
) -> Token:
    """
    Set the tenant for the current execution context.

    Returns:
        Token used to restore the previous context.
    """

    return _current_tenant.set(tenant)


def reset_current_tenant(
    token: Token,
) -> None:
    """
    Restore the previous tenant context.
    """

    _current_tenant.reset(token)


@contextmanager
def tenant_scope(
    tenant: TenantContext,
) -> Generator[TenantContext, None, None]:
    """
    Establish a tenant context for the duration of a block.

    The previous context is automatically restored when the
    block exits.
    """

    token = _current_tenant.set(tenant)

    try:
        yield tenant

    finally:
        _current_tenant.reset(token)


def assert_tenant_context(
    expected: TenantContext,
) -> None:
    """
    Verify that the expected tenant matches the active
    execution context.
    """

    current = get_current_tenant()

    if current.tenant_id != expected.tenant_id:
        raise RuntimeError(
            "Tenant context violation: "
            f"expected '{expected.tenant_id}', "
            f"but active tenant is '{current.tenant_id}'."
        )
