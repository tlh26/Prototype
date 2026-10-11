from datetime import datetime, timezone
from types import SimpleNamespace

from correlation.models import EvidenceLayer
from correlation.normaliser import EvidenceNormaliser


def test_normalise_instance_event():
    timestamp = datetime(2026, 9, 22, 20, 0, 0, tzinfo=timezone.utc)
    created_at = datetime(2026, 9, 22, 20, 0, 1, tzinfo=timezone.utc)

    event = SimpleNamespace(
        event_id="event-001",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=SimpleNamespace(value="authentication"),
        event_type=SimpleNamespace(value="SESSION_CREATED"),
        timestamp=timestamp,
        created_at=created_at,
        actor="root",
        uid=0,
        resource="/tmp/test",
        source="auth.log",
        source_path="/var/log/auth.log",
        details={"username": "root"},
        raw_data=b"test evidence",
        sha256="a" * 64,
        agent_id="agent-web-b",
        sequence=42,
    )

    result = EvidenceNormaliser().normalise_event(event)

    assert result.evidence_id == "event-001"
    assert result.tenant_id == "tenant-b"
    assert result.project_id == "tenant-b"
    assert result.instance_name == "web-b"
    assert result.layer == EvidenceLayer.INSTANCE

    assert result.event_timestamp == timestamp
    assert result.collected_at == created_at

    assert result.actor == "root"
    assert result.uid == 0
    assert result.attributes == {"username": "root"}

    assert result.sequence_start == 42
    assert result.sequence_end == 42

    assert result.provenance["source_table"] == "evidence_events"


def test_normalise_host_record():
    collected_at = datetime(2026, 9, 22, 20, 1, 0, tzinfo=timezone.utc)

    record = SimpleNamespace(
        evidence_id="auditd:incus-host:42:abc",
        tenant_id="tenant-b",
        tenant_hash="tenant-hash",
        project_id="tenant-b",
        instance_name="web-b",
        scope="incus-host",
        source="auditd",
        source_path="/var/log/audit/audit.log",
        acquisition_layer="host",
        acquired_from="incus-host",
        attribution_method="incus_subject",
        collected_at=collected_at,
        raw_data=b"type=SYSCALL msg=audit(123.456:42)",
        sha256="b" * 64,
        sequence_start=42,
        sequence_end=42,
        capture_id="capture-001",
        record_sha256="c" * 64,
    )

    result = EvidenceNormaliser().normalise_record(record)

    assert result.evidence_id == record.evidence_id
    assert result.tenant_id == "tenant-b"
    assert result.project_id == "tenant-b"
    assert result.instance_name == "web-b"
    assert result.layer == EvidenceLayer.HOST

    # Collection time is known; event time has not yet been parsed.
    assert result.event_timestamp is None
    assert result.collected_at == collected_at

    assert result.raw_data == record.raw_data
    assert result.sha256 == record.sha256

    assert result.sequence_start == 42
    assert result.sequence_end == 42

    assert result.provenance["source_table"] == "evidence_records"
    assert result.provenance["acquisition_layer"] == "host"
    assert result.provenance["attribution_method"] == "incus_subject"
    assert result.provenance["record_sha256"] == "c" * 64
