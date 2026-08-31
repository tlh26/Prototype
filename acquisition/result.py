# acquisition/result.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict


class AcquisitionResult(BaseModel):

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    collector: str
    source: str
    tenant_id: str
    instance_name: str
    acquired_at: datetime
    evidence_id: str
    sha256: str
    size_bytes: int
    success: bool
    metadata: dict[str, Any] = {}

class NormalizedAuditEvent(BaseModel):    
    event_id: str
    tenant_id: str
    instance_name: str
    audit_sequence: int
    timestamp: datetime
    event_types: list[str]
    actor: str | None
    uid: int | None
    auid: str | None
    executable: str | None
    command: str | None
    syscall: str | None
    success: bool | None
    path: str | None
    cwd: str | None
    audit_key: str | None
    source_evidence_id: str