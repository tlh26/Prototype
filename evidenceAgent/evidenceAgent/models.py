from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class EvidenceType(str, Enum):
    AUTHENTICATION = "authentication"
    TRACE = "trace"
    FILE = "file"


class EventType(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_TERMINATED = "SESSION_TERMINATED"

    RESOURCE_CREATE = "RESOURCE_CREATE"
    RESOURCE_READ = "RESOURCE_READ"
    RESOURCE_UPDATE = "RESOURCE_UPDATE"
    RESOURCE_DELETE = "RESOURCE_DELETE"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"

    FILE_CREATE = "FILE_CREATE"
    FILE_READ = "FILE_READ"
    FILE_MODIFY = "FILE_MODIFY"
    FILE_DELETE = "FILE_DELETE"
    FILE_RENAME = "FILE_RENAME"


class EvidenceEvent(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    event_id: str

    tenant_id: str
    instance_name: str

    evidence_type: EvidenceType
    event_type: EventType

    timestamp: datetime

    actor: str | None = None
    uid: int | None = None

    resource: str | None = None

    source: str
    source_path: str | None = None

    details: dict[str, Any] = {}

    sequence: int

    agent_id: str

    raw_data: bytes

    sha256: str

    created_at: datetime

    @classmethod
    def now(
        cls,
        *,
        event_id: str,
        tenant_id: str,
        instance_name: str,
        evidence_type: EvidenceType,
        event_type: EventType,
        sequence: int,
        agent_id: str,
        source: str,
        raw_data: bytes,
        actor: str | None = None,
        uid: int | None = None,
        resource: str | None = None,
        source_path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> "EvidenceEvent":

        timestamp = datetime.now(timezone.utc)

        import hashlib

        return cls(
            event_id=event_id,
            tenant_id=tenant_id,
            instance_name=instance_name,
            evidence_type=evidence_type,
            event_type=event_type,
            timestamp=timestamp,
            actor=actor,
            uid=uid,
            resource=resource,
            source=source,
            source_path=source_path,
            details=details or {},
            sequence=sequence,
            agent_id=agent_id,
            raw_data=raw_data,
            sha256=hashlib.sha256(raw_data).hexdigest(),
            created_at=timestamp,
        )