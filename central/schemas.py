from datetime import datetime
from typing import Any

from pydantic import BaseModel


class EvidenceEventRequest(BaseModel):
    event_id: str
    tenant_id: str
    instance_name: str

    evidence_type: str
    event_type: str

    timestamp: datetime

    actor: str | None = None
    uid: int | None = None
    resource: str | None = None

    source: str
    source_path: str | None = None

    details: dict[str, Any]

    sequence: int
    agent_id: str

    raw_data: str
    sha256: str

    created_at: datetime
