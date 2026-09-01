from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from evidenceAgent.evidenceAgent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


def test_evidence_event_creation():
    event = EvidenceEvent.now(
        event_id="event-001",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.AUTHENTICATION,
        event_type=EventType.LOGIN_SUCCESS,
        sequence=1,
        agent_id="agent-web-b",
        source="auth.log",
        raw_data=b"Accepted password for appuser\n",
        actor="appuser",
    )

    assert event.event_id == "event-001"
    assert event.tenant_id == "tenant-b"
    assert event.instance_name == "web-b"
    assert event.agent_id == "agent-web-b"

    assert event.evidence_type == EvidenceType.AUTHENTICATION
    assert event.event_type == EventType.LOGIN_SUCCESS

    assert event.sequence == 1
    assert event.raw_data == b"Accepted password for appuser\n"


def test_evidence_event_calculates_sha256():
    import hashlib

    raw = b"test evidence\n"

    event = EvidenceEvent.now(
        event_id="event-002",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.FILE,
        event_type=EventType.FILE_CREATE,
        sequence=1,
        agent_id="agent-web-b",
        source="filesystem",
        raw_data=raw,
    )

    expected = hashlib.sha256(raw).hexdigest()

    assert event.sha256 == expected


def test_evidence_event_is_immutable():
    event = EvidenceEvent.now(
        event_id="event-003",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.FILE,
        event_type=EventType.FILE_CREATE,
        sequence=1,
        agent_id="agent-web-b",
        source="filesystem",
        raw_data=b"hello",
    )

    with pytest.raises((ValidationError, TypeError)):
        event.tenant_id = "tenant-a"


def test_evidence_event_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        EvidenceEvent(
            event_id="event-004",
            tenant_id="tenant-b",
            instance_name="web-b",
            evidence_type=EvidenceType.FILE,
            event_type=EventType.FILE_CREATE,
            timestamp=datetime.now(timezone.utc),
            source="filesystem",
            sequence=1,
            agent_id="agent-web-b",
            raw_data=b"hello",
            sha256="abc",
            created_at=datetime.now(timezone.utc),
            unexpected_field="should-fail",
        )


def test_evidence_event_preserves_raw_data():
    raw = b"original forensic record\n"

    event = EvidenceEvent.now(
        event_id="event-005",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.FILE,
        event_type=EventType.FILE_MODIFY,
        sequence=10,
        agent_id="agent-web-b",
        source="filesystem",
        raw_data=raw,
    )

    assert event.raw_data == raw