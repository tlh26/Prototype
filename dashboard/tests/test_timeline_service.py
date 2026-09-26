from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from dashboard.services.timeline import TimelineService


class FakeCorrelationService:
    def __init__(self, evidence):
        self.evidence = evidence
        self.calls = []

    def correlate(self, *, tenant_id=None, instance_name=None, limit=None):
        self.calls.append(
            {
                "tenant_id": tenant_id,
                "instance_name": instance_name,
                "limit": limit,
            }
        )

        return SimpleNamespace(
            evidence=tuple(self.evidence),
        )


def make_evidence(
    evidence_id: str,
    timestamp: datetime | None,
):
    return SimpleNamespace(
        evidence_id=evidence_id,
        event_timestamp=timestamp,
    )


def test_build_returns_chronological_timeline():
    first_timestamp = datetime(
        2026,
        9,
        26,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    second_timestamp = datetime(
        2026,
        9,
        26,
        10,
        0,
        5,
        tzinfo=timezone.utc,
    )

    correlation_service = FakeCorrelationService(
        [
            make_evidence("event-002", second_timestamp),
            make_evidence("event-001", first_timestamp),
        ]
    )

    service = TimelineService(
        correlation_service=correlation_service,
    )

    entries = service.build(
        tenant_id="tenant-a",
        instance_name="web-a",
        limit=20,
    )

    assert [entry.evidence_id for entry in entries] == [
        "event-001",
        "event-002",
    ]

    assert correlation_service.calls == [
        {
            "tenant_id": "tenant-a",
            "instance_name": "web-a",
            "limit": 20,
        }
    ]


def test_build_excludes_evidence_without_event_timestamp():
    timestamp = datetime(
        2026,
        9,
        26,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    correlation_service = FakeCorrelationService(
        [
            make_evidence("event-001", timestamp),
            make_evidence("record-001", None),
        ]
    )

    service = TimelineService(
        correlation_service=correlation_service,
    )

    entries = service.build(
        tenant_id="tenant-a",
    )

    assert [entry.evidence_id for entry in entries] == [
        "event-001",
    ]