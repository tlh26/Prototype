# tests/acquisition/test_evidence_capture_storage_integration.py
from pathlib import Path

from acquisition.captureTarget import CaptureTarget
from acquisition.collectorRegistry import CollectorRegistry
from acquisition.evidenceCaptureService import EvidenceCaptureService
from acquisition.checkpoint import CheckpointStore
from acquisition.collectors.audit import AuditCollector
from acquisition.collectors.auditAttributor import IncusAuditAttributor
from evidence.enums import CloudPlatform
from evidence.tenant import TenantContext
from storage.evidenceRepo import SQLiteEvidenceRepository

AUDIT_LOG = "/var/log/audit/audit.log"


class MockHostExecutor:
    """
    Deterministic host executor for integration testing.

    Simulates:
        stat
        dd
    """

    def __init__(self, audit_data: bytes):
        self.audit_data = audit_data
        self.commands: list[list[str]] = []

    def exec(self, *, command: list[str]):
        from types import SimpleNamespace

        self.commands.append(command)

        if command[0] == "stat":
            return SimpleNamespace(
                returncode=0,
                stdout=(f"10 20 {len(self.audit_data)}\n").encode(),
                stderr=b"",
            )

        if command[0] == "dd":
            skip = 0
            count = len(self.audit_data)

            for argument in command:
                if argument.startswith("skip="):
                    skip = int(argument.split("=", 1)[1])
                elif argument.startswith("count="):
                    count = int(argument.split("=", 1)[1])

            return SimpleNamespace(
                returncode=0,
                stdout=self.audit_data[skip : skip + count],
                stderr=b"",
            )

        raise AssertionError(f"Unexpected host command: {command}")


def audit_record(
    sequence: int,
    subject: str,
) -> bytes:
    return (
        b"type=SYSCALL "
        + (f"msg=audit(" f"08/27/2026 19:35:34.612:" f"{sequence}" f"): ").encode()
        + f"subj={subject}\n".encode()
    )


def test_capture_persists_real_audit_evidence(
    tmp_path: Path,
):
    # ---------------------------------------------------------
    # Arrange
    # ---------------------------------------------------------

    audit_data = (
        audit_record(
            100,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            100,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            101,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            102,
            "incus-tenant-b_web-b_test",
        )
    )

    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    tenant = TenantContext(
        tenant_id="tenant-b",
        tenant_name="Tenant B",
        tenant_hash="tenant-b-hash",
        platform=CloudPlatform.INCUS,
        platform_project_id="tenant-b",
    )

    target = CaptureTarget(
        tenant=tenant,
        instance_name="web-b",
    )

    executor = MockHostExecutor(audit_data)

    checkpoint_store = CheckpointStore(tmp_path / "audit-checkpoint.json")

    collector = AuditCollector(
        executor=executor,
        checkpoint_store=checkpoint_store,
        attributor=IncusAuditAttributor(),
        host_id="test-host",
    )

    registry = CollectorRegistry()

    registry.register(collector)

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    # ---------------------------------------------------------
    # Act
    # ---------------------------------------------------------

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    # ---------------------------------------------------------
    # Assert manifest
    # ---------------------------------------------------------

    assert manifest.capture_id is not None

    assert len(manifest.successful_sources) >= 1

    # ---------------------------------------------------------
    # Assert evidence was persisted
    # ---------------------------------------------------------

    evidence = repository.list_evidence(
        capture_id=manifest.capture_id,
    )

    assert evidence

    for stored in evidence:
        assert stored.capture_id == (manifest.capture_id)

        assert stored.tenant_id == "tenant-b"
        assert stored.project_id == "tenant-b"
        assert stored.instance_name == "web-b"
        assert stored.source == "auditd"
        assert stored.raw_data
        assert stored.sha256
        assert stored.size_bytes == len(stored.raw_data)
        assert repository.verify_evidence_integrity(stored.evidence_id)
