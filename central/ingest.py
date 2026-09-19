from __future__ import annotations

import base64
import hashlib

from evidenceAgent.evidenceAgent.transportModels import (
    EvidenceBatch,
    EvidenceEnvelope,
)

from evidence.evidence import EvidenceRecord
from central.genericRepo import GenericEvidenceRepository


class IngestionError(RuntimeError):
    """Raised when evidence fails central validation."""


def decode_evidence(
    envelope: EvidenceEnvelope,
) -> bytes:
    """
    Decode and validate the raw evidence contained in an
    EvidenceEnvelope.
    """

    try:
        raw_data = base64.b64decode(
            envelope.raw_data_b64,
            validate=True,
        )
    except Exception as exc:
        raise IngestionError(
            f"Invalid Base64 for evidence "
            f"{envelope.evidence_id}"
        ) from exc

    if len(raw_data) != envelope.size_bytes:
        raise IngestionError(
            f"Size mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected {envelope.size_bytes}, "
            f"received {len(raw_data)}"
        )

    actual_sha256 = hashlib.sha256(
        raw_data
    ).hexdigest()

    if actual_sha256 != envelope.sha256:
        raise IngestionError(
            f"SHA-256 mismatch for evidence "
            f"{envelope.evidence_id}: "
            f"expected {envelope.sha256}, "
            f"calculated {actual_sha256}"
        )

    return raw_data


def envelope_to_record(
    envelope: EvidenceEnvelope,
) -> EvidenceRecord:
    """
    Convert a validated transport envelope into the
    canonical persisted EvidenceRecord.
    """

    raw_data = decode_evidence(envelope)

    return EvidenceRecord(
        evidence_id=envelope.evidence_id,

        tenant_id=envelope.tenant_id,
        tenant_hash=envelope.tenant_hash,

        project_id=envelope.project_id,
        instance_name=envelope.instance_name,

        scope=envelope.scope,

        source=envelope.source,
        source_path=envelope.source_path,

        acquisition_layer=envelope.acquisition_layer,
        acquired_from=envelope.acquired_from,
        attribution_method=envelope.attribution_method,

        collected_at=envelope.collected_at,

        raw_data=raw_data,

        sha256=envelope.sha256,
        size_bytes=envelope.size_bytes,

        sequence_start=envelope.sequence_start,
        sequence_end=envelope.sequence_end,

        capture_id=envelope.capture_id,
    )


def ingest_batch(
    *,
    batch: EvidenceBatch,
    repository: GenericEvidenceRepository,
) -> int:
    stored = 0

    for envelope in batch.evidence:
        record = envelope_to_record(envelope)

        existing = repository.get(record.evidence_id)

        if existing is not None:
            existing_sha256 = existing["sha256"]

            if existing_sha256 != record.sha256:
                raise IngestionError(
                    f"Evidence ID collision for {record.evidence_id}: "
                    "existing evidence has a different SHA-256"
                )

            # Same evidence already exists.
            # This is a safe retry.
            continue

        repository.save(record)
        stored += 1

    return stored