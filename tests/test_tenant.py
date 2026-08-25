import pytest
from pydantic import ValidationError
from evidence.tenant import TenantContext
from evidence.enums import CloudPlatform
from common.hashing import HashingService

hashing_service = HashingService()

def test_incus_tenant_context():
    tenant = TenantContext(
        tenant_id="cloud-a",
        tenant_name="tenant-a",
        tenant_hash=hashing_service.sha256("cloud-a"),
        platform=CloudPlatform.INCUS,
        platform_project_id="cloud-a",
    )

    assert tenant.tenant_id == "cloud-a"
    assert tenant.platform_project_id == "cloud-a"
    assert tenant.tenant_name == "tenant-a"
    assert tenant.platform == CloudPlatform.INCUS

def test_tenant_id_matches_project_id():
    tenant = TenantContext(
        tenant_id="cloud-a",
        tenant_name="tenant-a",
        tenant_hash=hashing_service.sha256("cloud-a"),
        platform=CloudPlatform.INCUS,
        platform_project_id="cloud-a",
    )

    assert tenant.tenant_id == tenant.platform_project_id


def test_tenant_context_is_immutable():
    tenant = TenantContext(
        tenant_id="cloud-a",
        tenant_name="tenant-a",
        tenant_hash=hashing_service.sha256("cloud-a"),
        platform=CloudPlatform.INCUS,
        platform_project_id="cloud-a",
    )

    with pytest.raises(ValidationError):
        tenant.tenant_id = "cloud-b"

    with pytest.raises(ValidationError):
        tenant.platform_project_id = "cloud-b"

    with pytest.raises(ValidationError):
        tenant.tenant_name = "tenant-b"


def test_tenant_platform():
    tenant = TenantContext(
        tenant_id="cloud-a",
        tenant_name="tenant-a",
        tenant_hash=hashing_service.sha256("cloud-a"),
        platform=CloudPlatform.INCUS,
        platform_project_id="cloud-a",
    )

    assert tenant.platform == CloudPlatform.INCUS


def test_tenant_context_is_immutable():
    tenant = TenantContext(
        tenant_id="cloud-a",
        tenant_name="tenant-a",
        tenant_hash=hashing_service.sha256("cloud-a"),
        platform=CloudPlatform.INCUS,
        platform_project_id="cloud-a",
    )

    with pytest.raises(ValidationError):
        tenant.platform = CloudPlatform.OPENSTACK

    assert tenant.platform == CloudPlatform.INCUS


def test_hash_dictionary_key_order_independent():
    first = {
        "tenant_id": "cloud-a",
        "platform": "incus",
    }

    second = {
        "platform": "incus",
        "tenant_id": "cloud-a",
    }

    assert HashingService.hash_dictionary(first) == \
           HashingService.hash_dictionary(second)

def test_tenant_hash_deterministic():
    identity = "incus:cloud-a"

    hash_a = HashingService.sha256(identity)
    hash_b = HashingService.sha256(identity)

    assert hash_a == hash_b