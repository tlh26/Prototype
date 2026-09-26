"""
Conceptually:
class EvidenceRecord(BaseModel):
    evidence_id: str

    event_type: EventType
    event_category: EvidenceCategory

    timestamp: datetime

    source: EvidenceSource

    metadata: EvidenceMetadata

    tenant: TenantContext | None

    actor: Actor | None

    resource: Resource | None

    provenance: Provenance

    integrity: IntegrityInformation

    custody: ChainOfCustody

    relationships: list[EvidenceRelationship]

    raw_data: dict

"""

# evidence/evidence.py

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EvidenceRecord(BaseModel):
    """
    Canonical persisted representation of evidence.

    EvidenceRecord describes one immutable evidence object that has
    been acquired and persisted by the central evidence repository.

    Design principles
    -----------------
    - raw_data is the authoritative evidence payload;
    - sha256 protects the raw payload;
    - record_sha256 protects the metadata describing the payload;
    - capture_id links the evidence to a capture manifest;
    - tenant/project/instance fields preserve provenance.

    This model does not:
        - collect evidence;
        - parse evidence;
        - correlate evidence;
        - access SQLite directly.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # --------------------------------------------------------------
    # Identity
    # --------------------------------------------------------------

    evidence_id: str

    capture_id: str | None = None

    # --------------------------------------------------------------
    # Tenant / infrastructure provenance
    # --------------------------------------------------------------

    tenant_id: str | None = None

    tenant_hash: str | None = None

    project_id: str | None = None

    instance_name: str | None = None

    scope: str

    # --------------------------------------------------------------
    # Source provenance
    # --------------------------------------------------------------

    source: str

    source_path: str

    acquisition_layer: str

    acquired_from: str

    attribution_method: str

    # --------------------------------------------------------------
    # Time
    # --------------------------------------------------------------

    collected_at: datetime

    # --------------------------------------------------------------
    # Raw evidence
    # --------------------------------------------------------------

    raw_data: bytes

    sha256: str

    size_bytes: int

    # --------------------------------------------------------------
    # Audit sequence information
    # --------------------------------------------------------------

    sequence_start: int | None = None

    sequence_end: int | None = None

    # --------------------------------------------------------------
    # Persisted record integrity
    # --------------------------------------------------------------

    record_sha256: str | None = None
