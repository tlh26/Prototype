from datetime import datetime, timezone

from correlation.attributes import AttributeExtractor
from correlation.models import CanonicalEvidence, EvidenceLayer


def make_evidence(**overrides):
    values = {
        "evidence_id": "event-001",
        "tenant_id": "tenant-b",
        "project_id": "tenant-b",
        "instance_name": "web-b",
        "layer": EvidenceLayer.INSTANCE,
        "evidence_type": "authentication",
        "event_type": "SESSION_CREATED",
        "source": "auth.log",
        "source_path": "/var/log/auth.log",
        "event_timestamp": datetime(
            2026,
            9,
            25,
            6,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        "collected_at": datetime(
            2026,
            9,
            25,
            6,
            0,
            1,
            tzinfo=timezone.utc,
        ),
        "actor": "root",
        "uid": 0,
        "resource": "/tmp/test",
        "attributes": {
            "username": "root",
            "action": "login",
        },
        "raw_data": b"test",
        "sha256": "a" * 64,
        "agent_id": "agent-web-b",
        "sequence_start": 42,
        "sequence_end": 42,
    }

    values.update(overrides)
    return CanonicalEvidence(**values)


def test_extracts_canonical_attributes():
    evidence = make_evidence()

    attributes = AttributeExtractor().extract(evidence)

    assert attributes["tenant_id"] == "tenant-b"
    assert attributes["project_id"] == "tenant-b"
    assert attributes["instance_name"] == "web-b"

    assert attributes["actor"] == "root"
    assert attributes["uid"] == 0
    assert attributes["resource"] == "/tmp/test"

    assert attributes["source"] == "auth.log"
    assert attributes["event_type"] == "SESSION_CREATED"
    assert attributes["evidence_type"] == "authentication"
    assert attributes["layer"] == "instance"


def test_extracts_temporal_attributes():
    evidence = make_evidence()

    attributes = AttributeExtractor().extract(evidence)

    assert attributes["event_timestamp"] == evidence.event_timestamp
    assert attributes["collected_at"] == evidence.collected_at


def test_extracts_source_specific_attributes():
    evidence = make_evidence()

    attributes = AttributeExtractor().extract(evidence)

    assert attributes["username"] == "root"
    assert attributes["action"] == "login"


def test_canonical_attributes_cannot_be_overwritten():
    evidence = make_evidence(
        attributes={
            "tenant_id": "tenant-a",
            "actor": "attacker",
            "username": "root",
        }
    )

    attributes = AttributeExtractor().extract(evidence)

    assert attributes["tenant_id"] == "tenant-b"
    assert attributes["actor"] == "root"
    assert attributes["username"] == "root"


def test_optional_attributes_are_omitted():
    evidence = make_evidence(
        tenant_id=None,
        project_id=None,
        instance_name=None,
        actor=None,
        uid=None,
        resource=None,
        source_path=None,
        event_timestamp=None,
        agent_id=None,
        sequence_start=None,
        sequence_end=None,
    )

    attributes = AttributeExtractor().extract(evidence)

    assert "tenant_id" not in attributes
    assert "project_id" not in attributes
    assert "instance_name" not in attributes
    assert "actor" not in attributes
    assert "uid" not in attributes
    assert "resource" not in attributes
    assert "source_path" not in attributes
    assert "event_timestamp" not in attributes
    assert "agent_id" not in attributes
    assert "sequence_start" not in attributes
