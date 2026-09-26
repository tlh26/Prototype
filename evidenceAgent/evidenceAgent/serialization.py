from __future__ import annotations

import base64

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acquisition.collectors.audit import AuditEvidence

from .transportModels import EvidenceEnvelope


def audit_evidence_to_envelope(
    evidence: AuditEvidence,
    *,
    capture_id: str | None = None,
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        evidence_id=evidence.evidence_id,
        tenant_id=evidence.tenant_id,
        tenant_hash=evidence.tenant_hash,
        project_id=evidence.project_id,
        instance_name=evidence.instance_name,
        scope=evidence.scope,
        source=evidence.source,
        source_path=evidence.source_path,
        acquisition_layer=evidence.acquisition_layer,
        acquired_from=evidence.acquired_from,
        attribution_method=evidence.attribution_method,
        collected_at=evidence.collected_at,
        raw_data_b64=base64.b64encode(evidence.raw_data).decode("ascii"),
        sha256=evidence.sha256,
        size_bytes=evidence.size_bytes,
        sequence_start=evidence.sequence_start,
        sequence_end=evidence.sequence_end,
        capture_id=capture_id,
    )
