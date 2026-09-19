from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EvidenceEnvelope(BaseModel):
    """
    Wire-format representation of evidence sent to central.

    This model deliberately uses Base64 for raw evidence because
    JSON cannot safely transport arbitrary bytes.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str

    tenant_id: str | None
    tenant_hash: str | None

    project_id: str | None
    instance_name: str | None

    scope: str

    source: str
    source_path: str

    acquisition_layer: str
    acquired_from: str
    attribution_method: str

    collected_at: datetime

    raw_data_b64: str

    sha256: str
    size_bytes: int

    sequence_start: int | None = None
    sequence_end: int | None = None

    capture_id: str | None = None


class EvidenceBatch(BaseModel):
    """
    Batch transported from an agent to central.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    agent_id: str
    # tenant_id: str | None
    # instance_name: str | None
    evidence: tuple[EvidenceEnvelope, ...]