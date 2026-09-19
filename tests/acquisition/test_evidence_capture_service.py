from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock

from acquisition.captureManifest import (
    CaptureStatus,
    SourceCaptureStatus,
)
from acquisition.captureTarget import CaptureTarget
from acquisition.collectorRegistry import CollectorRegistry
from acquisition.collectors.audit import AuditEvidence
from acquisition.collectors.base import CollectorError
from acquisition.evidenceCaptureService import (
    EvidenceCaptureService,
)
from evidence.tenant import (
    CloudPlatform,
    TenantContext,
)


# ============================================================================
# Test data helpers
# ============================================================================


def create_tenant(
    tenant_id: str = "tenant-b",
) -> TenantContext:
    """
    Create a valid TenantContext for service tests.
    """

    return TenantContext(
        tenant_id=tenant_id,
        tenant_name=f"Tenant {tenant_id}",
        tenant_hash=f"hash-{tenant_id}",
        platform=CloudPlatform.INCUS,
        platform_project_id=tenant_id,
    )


def create_target(
    *,
    tenant_id: str = "tenant-b",
    instance_name: str = "web-b",
) -> CaptureTarget:
    """
    Create a valid CaptureTarget for service tests.
    """

    return CaptureTarget(
        tenant=create_tenant(tenant_id),
        instance_name=instance_name,
    )


def create_audit_evidence(
    *,
    tenant_id: str = "tenant-b",
    instance_name: str = "web-b",
    evidence_id: str = "auditd:test-event-001",
    raw_data: bytes = b"test audit evidence",
) -> AuditEvidence:
    """
    Create valid AuditEvidence returned by a mocked collector.
    """

    import hashlib

    digest = hashlib.sha256(
        raw_data
    ).hexdigest()

    return AuditEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        tenant_hash=f"hash-{tenant_id}",
        project_id=tenant_id,
        instance_name=instance_name,
        scope=(
            f"{tenant_id}/"
            f"{instance_name}"
        ),
        source="auditd",
        source_path="/var/log/audit/audit.log",
        acquisition_layer="host",
        acquired_from="test-host",
        attribution_method="incus_subject",
        collected_at=datetime.now(
            timezone.utc
        ),
        raw_data=raw_data,
        sha256=digest,
        size_bytes=len(raw_data),
        sequence_start=100,
        sequence_end=100,
    )


def create_mock_repository() -> Mock:
    """
    Create a mock repository.

    We intentionally do not use spec=SQLiteEvidenceRepository here.

    These tests verify EvidenceCaptureService orchestration:
        save_manifest()
        save_audit()
        update_manifest()

    The repository implementation has its own tests.
    """

    repository = Mock()

    repository.save_manifest = Mock()
    repository.save_audit = Mock()
    repository.update_manifest = Mock()

    return repository


def create_service(
    *,
    collector,
):
    """
    Create EvidenceCaptureService with mocked dependencies.
    """

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.return_value = (
        collector
    )

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    return (
        service,
        registry,
        repository,
    )


# ============================================================================
# Successful capture
# ============================================================================


def test_capture_successfully_acquires_and_persists_evidence():
    """
    Verify the complete successful service flow:

        CaptureTarget
            ↓
        CaptureManifest
            ↓
        CollectorRegistry
            ↓
        Collector
            ↓
        AuditEvidence
            ↓
        Repository
            ↓
        Completed CaptureManifest
    """

    target = create_target()

    evidence = create_audit_evidence()

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    (
        service,
        registry,
        repository,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    # ------------------------------------------------------------------
    # Manifest identity
    # ------------------------------------------------------------------

    assert manifest.capture_id

    assert (
        manifest.tenant_id
        == target.tenant.tenant_id
    )

    assert (
        manifest.tenant_hash
        == target.tenant.tenant_hash
    )

    assert (
        manifest.project_id
        == target.tenant.platform_project_id
    )

    assert (
        manifest.instance_name
        == target.instance_name
    )

    # ------------------------------------------------------------------
    # Collector selection
    # ------------------------------------------------------------------

    registry.get.assert_called_once_with(
        "auditd"
    )

    # ------------------------------------------------------------------
    # Collector invocation
    # ------------------------------------------------------------------

    collector.collect.assert_called_once_with(
        tenant=target.tenant,
        instance_name=target.instance_name,
    )

    # ------------------------------------------------------------------
    # Source result
    # ------------------------------------------------------------------

    assert len(manifest.sources) == 1

    result = manifest.sources[0]

    assert result.source == "auditd"

    assert (
        result.status
        == SourceCaptureStatus.SUCCESS
    )

    assert (
        result.evidence_id
        == evidence.evidence_id
    )

    assert (
        result.sha256
        == evidence.sha256
    )

    assert (
        result.size_bytes
        == evidence.size_bytes
    )

    # ------------------------------------------------------------------
    # Overall status
    # ------------------------------------------------------------------

    assert (
        manifest.status
        == CaptureStatus.SUCCESS
    )

    assert manifest.completed_at is not None

    # ------------------------------------------------------------------
    # Evidence persistence
    # ------------------------------------------------------------------

    repository.save_audit.assert_called_once()

    args, kwargs = (
        repository.save_audit.call_args
    )

    assert args == (evidence,)

    assert (
        kwargs["capture_id"]
        == manifest.capture_id
    )

    # ------------------------------------------------------------------
    # Completed manifest persistence
    # ------------------------------------------------------------------

    repository.update_manifest.assert_called_once_with(
        manifest
    )


# ============================================================================
# Manifest ordering
# ============================================================================


def test_manifest_is_persisted_before_evidence():
    """
    The initial manifest must be persisted before evidence.

    This is important because evidence.capture_id references
    the capture manifest in the database.
    """

    target = create_target()

    evidence = create_audit_evidence()

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    repository = create_mock_repository()

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.return_value = (
        collector
    )

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    call_order = []

    def save_manifest(manifest):
        call_order.append(
            "save_manifest"
        )

    def save_audit(
        evidence,
        *,
        capture_id,
    ):
        call_order.append(
            "save_audit"
        )

    def update_manifest(manifest):
        call_order.append(
            "update_manifest"
        )

    repository.save_manifest.side_effect = (
        save_manifest
    )

    repository.save_audit.side_effect = (
        save_audit
    )

    repository.update_manifest.side_effect = (
        update_manifest
    )

    service.capture(
        target=target,
        sources=["auditd"],
    )

    assert call_order == [
        "save_manifest",
        "save_audit",
        "update_manifest",
    ]


# ============================================================================
# Capture ID propagation
# ============================================================================


def test_capture_id_is_propagated_to_evidence():
    """
    The capture ID generated by the service must be supplied
    to repository.save_audit().
    """

    target = create_target()

    evidence = create_audit_evidence()

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    (
        service,
        _,
        repository,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    repository.save_audit.assert_called_once()

    _, kwargs = (
        repository.save_audit.call_args
    )

    assert (
        kwargs["capture_id"]
        == manifest.capture_id
    )


# ============================================================================
# Integrity metadata
# ============================================================================


def test_successful_source_records_integrity_metadata():
    """
    The CaptureSourceResult must contain the evidence SHA-256
    and size information.
    """

    target = create_target()

    evidence = create_audit_evidence(
        raw_data=b"known raw evidence"
    )

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    (
        service,
        _,
        _,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    result = manifest.sources[0]

    assert (
        result.sha256
        == evidence.sha256
    )

    assert (
        result.size_bytes
        == len(evidence.raw_data)
    )


# ============================================================================
# Source failure
# ============================================================================


def test_source_failure_does_not_abort_capture():
    """
    A collector failure must be represented in the manifest
    rather than raised to the caller.
    """

    target = create_target()

    collector = Mock()

    collector.collect.side_effect = (
        CollectorError(
            "audit acquisition failed",
            source="auditd",
        )
    )

    (
        service,
        _,
        repository,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    # ------------------------------------------------------------------
    # Capture itself completes
    # ------------------------------------------------------------------

    assert manifest.capture_id

    assert len(manifest.sources) == 1

    # ------------------------------------------------------------------
    # Source failed
    # ------------------------------------------------------------------

    result = manifest.sources[0]

    assert result.source == "auditd"

    assert (
        result.status
        == SourceCaptureStatus.FAILED
    )

    assert (
        "audit acquisition failed"
        in result.error
    )

    # ------------------------------------------------------------------
    # No evidence should be persisted
    # ------------------------------------------------------------------

    repository.save_audit.assert_not_called()

    # ------------------------------------------------------------------
    # Final manifest should still be persisted
    # ------------------------------------------------------------------

    repository.update_manifest.assert_called_once_with(
        manifest
    )

    assert (
        manifest.status
        == CaptureStatus.FAILED
    )


# ============================================================================
# Invalid evidence type
# ============================================================================


def test_invalid_evidence_type_is_recorded_as_failure():
    """
    The service must reject evidence returned by a collector
    if it is not an AuditEvidence instance.
    """

    target = create_target()

    collector = Mock()

    collector.collect.return_value = (
        "this is not evidence"
    )

    (
        service,
        registry,
        repository,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    registry.get.assert_called_once_with(
        "auditd"
    )

    assert len(manifest.sources) == 1

    result = manifest.sources[0]

    assert (
        result.status
        == SourceCaptureStatus.FAILED
    )

    assert (
        "Unsupported evidence type"
        in result.error
    )

    repository.save_audit.assert_not_called()

    assert (
        manifest.status
        == CaptureStatus.FAILED
    )


# ============================================================================
# Multiple successful sources
# ============================================================================


def test_multiple_successful_sources_produce_successful_manifest():
    """
    If all requested sources succeed, the final manifest
    must have SUCCESS status.
    """

    target = create_target()

    evidence_1 = create_audit_evidence(
        evidence_id="auditd:event-001"
    )

    evidence_2 = create_audit_evidence(
        evidence_id="auditd:event-002",
        raw_data=b"second audit event",
    )

    collector_1 = Mock()

    collector_1.collect.return_value = (
        evidence_1
    )

    collector_2 = Mock()

    collector_2.collect.return_value = (
        evidence_2
    )

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.side_effect = [
        collector_1,
        collector_2,
    ]

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=[
            "auditd",
            "auditd",
        ],
    )

    assert len(manifest.sources) == 2

    assert all(
        result.status
        == SourceCaptureStatus.SUCCESS
        for result in manifest.sources
    )

    assert (
        manifest.status
        == CaptureStatus.SUCCESS
    )

    assert (
        repository.save_audit.call_count
        == 2
    )


# ============================================================================
# Partial capture
# ============================================================================


def test_partial_capture_when_one_source_fails():
    """
    If at least one source succeeds and at least one fails,
    the overall capture must be PARTIAL.
    """

    target = create_target()

    successful_evidence = (
        create_audit_evidence(
            evidence_id="auditd:event-001"
        )
    )

    successful_collector = Mock()

    successful_collector.collect.return_value = (
        successful_evidence
    )

    failing_collector = Mock()

    failing_collector.collect.side_effect = (
        CollectorError(
            "source unavailable",
            source="other-source",
        )
    )

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.side_effect = [
        successful_collector,
        failing_collector,
    ]

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=[
            "auditd",
            "other-source",
        ],
    )

    assert len(manifest.sources) == 2

    statuses = [
        result.status
        for result in manifest.sources
    ]

    assert (
        SourceCaptureStatus.SUCCESS
        in statuses
    )

    assert (
        SourceCaptureStatus.FAILED
        in statuses
    )

    assert (
        manifest.status
        == CaptureStatus.PARTIAL
    )

    # Only the successful evidence is persisted.
    assert (
        repository.save_audit.call_count
        == 1
    )


# ============================================================================
# All sources failed
# ============================================================================


def test_all_failed_sources_produce_failed_manifest():
    """
    If every requested source fails, the overall capture
    must be FAILED.
    """

    target = create_target()

    collector = Mock()

    collector.collect.side_effect = (
        CollectorError(
            "audit source unavailable",
            source="auditd",
        )
    )

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.return_value = (
        collector
    )

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=[
            "auditd",
            "auditd",
        ],
    )

    assert len(manifest.sources) == 2

    assert all(
        result.status
        == SourceCaptureStatus.FAILED
        for result in manifest.sources
    )

    assert (
        manifest.status
        == CaptureStatus.FAILED
    )

    repository.save_audit.assert_not_called()


# ============================================================================
# Missing collector
# ============================================================================


def test_missing_collector_is_recorded_as_source_failure():
    """
    A collector registry failure must be recorded as a
    failed source rather than aborting the capture.
    """

    target = create_target()

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.side_effect = (
        CollectorError(
            "collector not registered",
            source="auditd",
        )
    )

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    assert len(manifest.sources) == 1

    result = manifest.sources[0]

    assert (
        result.status
        == SourceCaptureStatus.FAILED
    )

    assert (
        "collector not registered"
        in result.error
    )

    repository.save_audit.assert_not_called()

    assert (
        manifest.status
        == CaptureStatus.FAILED
    )


# ============================================================================
# Repository failure
# ============================================================================


def test_evidence_repository_failure_is_recorded_as_source_failure():
    """
    If evidence persistence fails, the source must not be reported
    as successful.
    """

    target = create_target()

    evidence = create_audit_evidence()

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    registry = Mock(
        spec=CollectorRegistry
    )

    registry.get.return_value = (
        collector
    )

    repository = create_mock_repository()

    repository.save_audit.side_effect = (
        RuntimeError(
            "database write failed"
        )
    )

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    result = manifest.sources[0]

    assert (
        result.status
        == SourceCaptureStatus.FAILED
    )

    assert (
        "database write failed"
        in result.error
    )

    assert (
        manifest.status
        == CaptureStatus.FAILED
    )

    repository.save_audit.assert_called_once()

    repository.update_manifest.assert_called_once_with(
        manifest
    )


# ============================================================================
# Completed manifest
# ============================================================================


def test_completed_manifest_is_persisted():
    """
    The final completed immutable manifest must be passed to
    repository.update_manifest().
    """

    target = create_target()

    evidence = create_audit_evidence()

    collector = Mock()

    collector.collect.return_value = (
        evidence
    )

    (
        service,
        _,
        repository,
    ) = create_service(
        collector=collector,
    )

    manifest = service.capture(
        target=target,
        sources=["auditd"],
    )

    repository.update_manifest.assert_called_once_with(
        manifest
    )

    assert manifest.sources

    assert (
        manifest.completed_at is not None
    )


# ============================================================================
# Empty source list
# ============================================================================


def test_empty_source_list_completes_without_collectors():
    """
    If no sources are requested, no collector should be selected
    and no evidence should be persisted.

    CaptureManifest stores sources as an immutable tuple.
    """

    target = create_target()

    registry = Mock(
        spec=CollectorRegistry
    )

    repository = create_mock_repository()

    service = EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )

    manifest = service.capture(
        target=target,
        sources=[],
    )

    assert manifest.capture_id

    # CaptureManifest.sources is tuple[CaptureSourceResult, ...].
    assert manifest.sources == ()

    # No collector should have been requested.
    registry.get.assert_not_called()

    # No evidence should have been persisted.
    repository.save_audit.assert_not_called()

    # Initial and completed manifests should still be persisted.
    repository.save_manifest.assert_called_once()

    repository.update_manifest.assert_called_once_with(
        manifest
    )

    # With zero failed and zero successful sources,
    # CaptureManifest.complete() returns SUCCESS.
    assert (
        manifest.status
        == CaptureStatus.SUCCESS
    )

    assert (
        manifest.completed_at is not None
    )