from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from correlation.lastKnownEvidence import LastKnownEvidenceStore
from evidenceAgent.evidenceAgent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


def test_cache_returns_most_recent_events_and_records_in_chronological_order(
    tmp_path,
):
    store = LastKnownEvidenceStore(tmp_path / "last-known.db")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    events = tuple(
        EvidenceEvent(
            event_id=f"event-{index}",
            tenant_id="tenant-a",
            instance_name="web-a",
            evidence_type=EvidenceType.TRACE,
            event_type=EventType.RESOURCE_ACCESS,
            timestamp=start + timedelta(minutes=index),
            source="test",
            details={},
            sequence=index,
            agent_id="agent-a",
            raw_data=b"event",
            sha256="event-hash",
            created_at=start + timedelta(minutes=index),
        )
        for index in range(1, 4)
    )
    store.save_events(events)

    with store._connect() as connection:
        for index in range(1, 4):
            collected_at = start + timedelta(minutes=index)
            connection.execute(
                """
                INSERT INTO records(evidence_id, payload, cached_at)
                VALUES (?, ?, ?)
                """,
                (
                    f"record-{index}",
                    json.dumps(
                        {
                            "evidence_id": f"record-{index}",
                            "tenant_id": "tenant-a",
                            "instance_name": "web-a",
                            "collected_at": collected_at.isoformat(),
                        }
                    ),
                    collected_at.isoformat(),
                ),
            )

    cached_events = store.get_events(limit=2)
    cached_records = store.get_records(limit=2)

    assert [event["event_id"] for event in cached_events] == [
        "event-2",
        "event-3",
    ]
    assert [record["evidence_id"] for record in cached_records] == [
        "record-2",
        "record-3",
    ]
