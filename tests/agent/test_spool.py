from pathlib import Path

from agent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)
from agent.spool import EvidenceSpool


def make_event(sequence=1):
    return EvidenceEvent.now(
        event_id=f"event-{sequence}",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.FILE,
        event_type=EventType.FILE_CREATE,
        sequence=sequence,
        agent_id="agent-web-b",
        source="filesystem",
        source_path="/tmp/test.txt",
        resource="/tmp/test.txt",
        raw_data=b"test evidence\n",
    )


def test_spool_creates_directory(tmp_path):
    spool_path = tmp_path / "spool"

    EvidenceSpool(str(spool_path))

    assert spool_path.exists()


def test_event_can_be_stored(tmp_path):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    event = make_event()

    path = spool.store(event)

    assert path.exists()
    assert path.suffix == ".json"


def test_pending_returns_stored_events(tmp_path):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    spool.store(make_event(1))
    spool.store(make_event(2))

    pending = spool.pending()

    assert len(pending) == 2


def test_pending_is_sorted_by_filename(tmp_path):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    spool.store(make_event(2))
    spool.store(make_event(1))

    pending = spool.pending()

    assert pending[0].name.startswith(
        "00000000000000000001"
    )


def test_spooled_event_contains_raw_data(tmp_path):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    event = make_event()

    path = spool.store(event)

    text = path.read_text(
        encoding="utf-8"
    )

    assert "test evidence" in text


def test_spool_event_can_be_removed(tmp_path):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(make_event())

    assert path.exists()

    spool.remove(path)

    assert not path.exists()