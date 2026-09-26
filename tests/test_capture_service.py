from unittest.mock import Mock

from acquisition.captureTarget import CaptureTarget
from acquisition.captureManifest import (
    CaptureStatus,
)
from acquisition.collectorRegistry import (
    CollectorRegistry,
)
from acquisition.evidenceCaptureService import (
    EvidenceCaptureService,
)
from acquisition.collectors.audit import AuditEvidence


def test_capture_service_captures_audit_evidence():

    tenant = Mock()

    tenant.tenant_id = "tenant-b"
    tenant.tenant_hash = "tenant-hash-b"
    tenant.platform_project_id = "tenant-b"

    target = CaptureTarget(
        tenant=tenant,
        instance_name="web-b",
    )

    collector = Mock()

    collector.source = "auditd"

    evidence = AuditEvidence(
        evidence_id="evidence-001",
        tenant_id="tenant-b",
        tenant_hash="tenant-hash-b",
        project_id="tenant-b",
        instance_name="web-b",
        source="auditd",
        source_path="/var/log/audit/audit.log",
        collected_at=(
            __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        ),
        raw_data=b"audit evidence",
        sha256="a" * 64,
        size_bytes=14,
        sequence_start=933,
        sequence_end=933,
    )

    collector.collect.return_value = evidence

    registry = CollectorRegistry()

    registry.register(collector)

    repository = Mock()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    assert manifest.status == CaptureStatus.SUCCESS

    assert manifest.evidence_count == 1

    assert manifest.sources[0].evidence_id == "evidence-001"

    collector.collect.assert_called_once_with(
        tenant=tenant,
        instance_name="web-b",
    )

    repository.save_audit.assert_called_once()
    repository.save_manifest.assert_called_once()


def test_capture_service_records_source_failure():

    tenant = Mock()

    tenant.tenant_id = "tenant-b"
    tenant.tenant_hash = "tenant-hash-b"
    tenant.platform_project_id = "tenant-b"

    target = CaptureTarget(
        tenant=tenant,
        instance_name="web-b",
    )

    collector = Mock()

    collector.source = "auditd"

    collector.collect.side_effect = RuntimeError("audit log unavailable")

    registry = CollectorRegistry()

    registry.register(collector)

    repository = Mock()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    assert manifest.status.value == "failed"

    assert manifest.evidence_count == 0

    assert manifest.sources[0].error == "audit log unavailable"

    repository.save_manifest.assert_called_once()
