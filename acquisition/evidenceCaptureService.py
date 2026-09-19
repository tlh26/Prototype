# acquisition/evidenceCaptureService.py
from __future__ import annotations

import uuid

from acquisition.captureManifest import (
    CaptureManifest,
    CaptureSourceResult,
    SourceCaptureStatus,
)
from acquisition.captureTarget import CaptureTarget
from acquisition.collectorRegistry import CollectorRegistry
from acquisition.collectors.audit import (
    AuditCollectionResult,
    AuditCollector,
    AuditEvidence,
)
from acquisition.collectors.base import CollectorError
from storage.evidenceRepo import SQLiteEvidenceRepository


class EvidenceCaptureService:

    def __init__(
        self,
        *,
        registry: CollectorRegistry,
        repository: SQLiteEvidenceRepository,
    ) -> None:
        self.registry = registry
        self.repository = repository

    def capture(
        self,
        *,
        target: CaptureTarget,
        sources: list[str],
    ) -> CaptureManifest:
        """
        Execute an evidence capture operation.

        The manifest is persisted before any evidence is acquired.
        Each source is isolated so that one source failure does not
        abort the complete capture.
        """

        capture_id = str(uuid.uuid4())

        manifest = CaptureManifest.create(
            capture_id=capture_id,
            tenant_id=target.tenant.tenant_id,
            tenant_hash=target.tenant.tenant_hash,
            project_id=target.tenant.platform_project_id,
            instance_name=target.instance_name,
        )

        # Persist the initial manifest before acquiring evidence.
        self.repository.save_manifest(manifest)

        results: list[CaptureSourceResult] = []

        for source in sources:
            results.append(
                self._capture_source(
                    capture_id=capture_id,
                    target=target,
                    source=source,
                )
            )

        # Complete the immutable manifest with source results.
        manifest = manifest.complete(results)

        # Persist final capture state.
        self.repository.update_manifest(manifest)

        return manifest

    def _capture_source(
        self,
        *,
        capture_id: str,
        target: CaptureTarget,
        source: str,
    ) -> CaptureSourceResult:
        """
        Acquire and persist one evidence source.

        AuditCollector has a special incremental collection contract.
        Other collectors retain the original collect() contract.
        """

        try:
            collector = self.registry.get(source)

            if isinstance(collector, AuditCollector):
                return self._capture_audit_collection(
                    capture_id=capture_id,
                    collector=collector,
                    source=source,
                )

            # Preserve the original collector contract used by
            # generic collectors and the existing unit tests.
            evidence = collector.collect(
                tenant=target.tenant,
                instance_name=target.instance_name,
            )

            if not isinstance(evidence, AuditEvidence):
                raise CollectorError(
                    f"Unsupported evidence type returned "
                    f"by collector '{source}'",
                    source=source,
                )

            self.repository.save_audit(
                evidence,
                capture_id=capture_id,
            )

            return CaptureSourceResult(
                source=source,
                status=SourceCaptureStatus.SUCCESS,
                evidence_id=evidence.evidence_id,
                sha256=evidence.sha256,
                size_bytes=evidence.size_bytes,
            )

        except Exception as exc:
            return CaptureSourceResult(
                source=source,
                status=SourceCaptureStatus.FAILED,
                error=str(exc),
            )

    def _capture_audit_collection(
        self,
        *,
        capture_id: str,
        collector: AuditCollector,
        source: str,
    ) -> CaptureSourceResult:
        """
        Acquire and persist an incremental audit collection.

        The audit checkpoint is committed only after every evidence
        item returned by collect_new() has been successfully persisted.
        """

        collection = collector.collect_new()

        if not isinstance(collection, AuditCollectionResult):
            raise CollectorError(
                "Audit collector returned an unsupported "
                "collection result",
                source=source,
            )

        # Persist every newly collected audit evidence item.
        for evidence in collection.evidence:
            if not isinstance(evidence, AuditEvidence):
                raise CollectorError(
                    "Audit collector returned an unsupported "
                    "evidence type",
                    source=source,
                )

            self.repository.save_audit(
                evidence,
                capture_id=capture_id,
            )

        # IMPORTANT:
        #
        # Do not advance the checkpoint until all evidence has been
        # persisted successfully. Otherwise a persistence failure could
        # cause evidence to be skipped during the next capture.
        collector.commit_checkpoint(
            collection.checkpoint
        )

        # A successful collection may legitimately contain no new
        # evidence, for example when the audit log has not changed.
        if not collection.evidence:
            return CaptureSourceResult(
                source=source,
                status=SourceCaptureStatus.SUCCESS,
            )

        # CaptureSourceResult currently represents one source with
        # single-evidence metadata. AuditCollector can return multiple
        # evidence records, so use the first record here for backwards
        # compatibility while all records have already been persisted.
        first = collection.evidence[0]

        return CaptureSourceResult(
            source=source,
            status=SourceCaptureStatus.SUCCESS,
            evidence_id=first.evidence_id,
            sha256=first.sha256,
            size_bytes=first.size_bytes,
        )