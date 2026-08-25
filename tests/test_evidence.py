from evidence.tenant import TenantContext
from evidence.enums import CloudPlatform
from evidence.evidence import EvidenceRecord


def create_tenant(project_id: str) -> TenantContext:
    return TenantContext(
        tenant_id=project_id,
        tenant_name=f"tenant-{project_id.split('-')[-1]}",
        platform=CloudPlatform.INCUS,
        platform_project_id=project_id,
    )


def test_evidence_record_contains_tenant_context():
    tenant = create_tenant("cloud-a")

    evidence = EvidenceRecord(
        # Add the other required EvidenceRecord fields here
        tenant=tenant,
    )

    assert evidence.tenant == tenant