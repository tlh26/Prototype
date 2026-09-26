import pytest

from evidence.tenant import TenantContext
from evidence.enums import CloudPlatform
from common.context import (
    get_current_tenant,
    set_current_tenant,
    reset_current_tenant,
    tenant_scope,
    assert_tenant_context,
)
from common.hashing import HashingService

hashing_service = HashingService()


def create_tenant(project_id: str) -> TenantContext:
    return TenantContext(
        tenant_id=project_id,
        tenant_name=f"tenant-{project_id.split('-')[-1]}",
        tenant_hash=hashing_service.sha256(f"incus:{project_id}"),
        platform=CloudPlatform.INCUS,
        platform_project_id=project_id,
    )


def test_get_current_tenant_raises_when_no_context():
    with pytest.raises(RuntimeError, match="No tenant context is active"):
        get_current_tenant()


def test_tenant_scope_sets_current_tenant():
    tenant = create_tenant("cloud-a")

    with tenant_scope(tenant):
        assert get_current_tenant() == tenant


def test_tenant_scope_restores_previous_context():
    tenant = create_tenant("cloud-a")

    with tenant_scope(tenant):
        assert get_current_tenant() == tenant

    with pytest.raises(RuntimeError, match="No tenant context is active"):
        get_current_tenant()


def test_nested_tenant_scopes_switch_context():
    tenant_a = create_tenant("cloud-a")
    tenant_b = create_tenant("cloud-b")

    with tenant_scope(tenant_a):
        assert get_current_tenant() == tenant_a

        with tenant_scope(tenant_b):
            assert get_current_tenant() == tenant_b

        assert get_current_tenant() == tenant_a


def test_nested_tenant_scopes_restore_to_empty_context():
    tenant_a = create_tenant("cloud-a")
    tenant_b = create_tenant("cloud-b")

    with pytest.raises(RuntimeError, match="No tenant context is active"):
        get_current_tenant()

    with tenant_scope(tenant_a):
        assert get_current_tenant() == tenant_a

        with tenant_scope(tenant_b):
            assert get_current_tenant() == tenant_b

        assert get_current_tenant() == tenant_a

    with pytest.raises(RuntimeError, match="No tenant context is active"):
        get_current_tenant()


def test_set_and_reset_current_tenant():
    tenant = create_tenant("cloud-a")

    token = set_current_tenant(tenant)

    try:
        assert get_current_tenant() == tenant

    finally:
        reset_current_tenant(token)

    with pytest.raises(RuntimeError, match="No tenant context is active"):
        get_current_tenant()


def test_set_current_tenant_replaces_previous_context():
    tenant_a = create_tenant("cloud-a")
    tenant_b = create_tenant("cloud-b")

    token_a = set_current_tenant(tenant_a)

    try:
        assert get_current_tenant() == tenant_a

        token_b = set_current_tenant(tenant_b)

        try:
            assert get_current_tenant() == tenant_b

        finally:
            reset_current_tenant(token_b)

        assert get_current_tenant() == tenant_a

    finally:
        reset_current_tenant(token_a)


def test_assert_tenant_context_succeeds_for_matching_tenant():
    tenant = create_tenant("cloud-a")

    with tenant_scope(tenant):
        assert_tenant_context(tenant)


def test_assert_tenant_context_raises_for_different_tenant():
    tenant_a = create_tenant("cloud-a")
    tenant_b = create_tenant("cloud-b")

    with tenant_scope(tenant_a):
        with pytest.raises(
            RuntimeError,
            match="Tenant context violation",
        ):
            assert_tenant_context(tenant_b)
