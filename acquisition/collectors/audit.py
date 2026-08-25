# acquisition/collectors/audit.py

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class EvidenceSource(str, Enum):
    AUDITD = "auditd"


class AuditEvidence(BaseModel):
    """
    Immutable representation of an acquired auditd evidence object.

    The raw evidence is deliberately retained rather than replaced by
    parsed/normalized fields.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str

    tenant_id: str
    tenant_hash: str

    instance_name: str

    source: EvidenceSource = EvidenceSource.AUDITD

    source_path: str

    collected_at: datetime

    raw_data: bytes

    sha256: str

    size_bytes: int

    sequence_start: Optional[int] = None
    sequence_end: Optional[int] = None