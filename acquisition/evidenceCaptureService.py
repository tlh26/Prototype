from __future__ import annotations

import uuid

from acquisition.captureManifest import (
    CaptureManifest,
    CaptureSourceResult,
    SourceCaptureStatus,
)
from acquisition.captureTarget import CaptureTarget
from acquisition.collectorRegistry import CollectorRegistry
from acquisition.collectors.audit import AuditEvidence
from acquisition.collectors.base import CollectorError
from storage.evidenceRepo import (
    SQLiteEvidenceRepository,
)


class EvidenceCaptureService:
    """
    Orchestrates evidence acquisition for a CaptureTarget.

    Responsibilities:

        1. Create a capture manifest.
        2. Persist the initial capture manifest.
        3. Select the requested collector.
        4. Execute evidence acquisition.
        5. Persist acquired evidence.
        6. Complete the capture manifest.
        7. Persist the completed manifest.

    The service does not interpret evidence.

    Acquisition flow:

        CaptureTarget
             |
             v
        Create capture ID
             |
             v
        Initial CaptureManifest
             |
             v
        Persist manifest
             |
             v
        Collector
             |
             v
        Evidence
             |
             v
        SHA-256 verification
             |
             v
        Persist evidence
             |
             v
        Complete manifest
             |
             v
        Update manifest
    """

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

        The initial manifest is persisted before evidence acquisition
        so that evidence records can safely reference capture_id through
        the database foreign key.

        Each source is attempted independently. Therefore:

            all successful -> SUCCESS
            some successful -> PARTIAL
            none successful -> FAILED
        """

        capture_id = str(
            uuid.uuid4()
        )

        # --------------------------------------------------------------
        # 1. Create initial immutable manifest
        # --------------------------------------------------------------

        manifest = CaptureManifest.create(
            capture_id=capture_id,

            tenant_id=target.tenant.tenant_id,

            tenant_hash=target.tenant.tenant_hash,

            project_id=target.tenant.platform_project_id,

            instance_name=target.instance_name,
        )

        # --------------------------------------------------------------
        # 2. Persist initial manifest
        #
        # This must happen before save_audit() because evidence.capture_id
        # references capture_manifests.capture_id.
        # --------------------------------------------------------------

        self.repository.save_manifest(
            manifest
        )

        # --------------------------------------------------------------
        # 3. Acquire each requested evidence source
        # --------------------------------------------------------------

        results: list[CaptureSourceResult] = []

        for source in sources:

            result = self._capture_source(
                capture_id=capture_id,

                target=target,

                source=source,
            )

            results.append(
                result
            )

        # --------------------------------------------------------------
        # 4. Complete immutable manifest
        # --------------------------------------------------------------

        manifest = manifest.complete(
            results
        )

        # --------------------------------------------------------------
        # 5. Persist completed manifest
        # --------------------------------------------------------------

        self.repository.update_manifest(
            manifest
        )

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

        Failure of one source does not abort the entire capture.
        Instead, the failure is recorded in the manifest.
        """

        try:

            # ----------------------------------------------------------
            # Select collector
            # ----------------------------------------------------------

            collector = self.registry.get(
                source
            )

            # ----------------------------------------------------------
            # Acquire evidence
            # ----------------------------------------------------------

            evidence = collector.collect(
                tenant=target.tenant,

                instance_name=target.instance_name,
            )

            # ----------------------------------------------------------
            # Validate evidence type
            # ----------------------------------------------------------

            if not isinstance(
                evidence,
                AuditEvidence,
            ):
                raise CollectorError(
                    f"Unsupported evidence type returned "
                    f"by collector '{source}'",
                    source=source,
                )

            # ----------------------------------------------------------
            # Persist evidence
            #
            # SQLiteEvidenceRepository independently verifies the
            # SHA-256 of raw_data before inserting the record.
            # ----------------------------------------------------------

            self.repository.save_audit(
                evidence,

                capture_id=capture_id,
            )

            # ----------------------------------------------------------
            # Report successful source
            # ----------------------------------------------------------

            return CaptureSourceResult(
                source=source,

                status=SourceCaptureStatus.SUCCESS,

                evidence_id=evidence.evidence_id,

                sha256=evidence.sha256,

                size_bytes=evidence.size_bytes,
            )

        except Exception as exc:

            # ----------------------------------------------------------
            # A source failure is recorded rather than aborting the
            # complete capture operation.
            # ----------------------------------------------------------

            return CaptureSourceResult(
                source=source,

                status=SourceCaptureStatus.FAILED,

                error=str(exc),
            )