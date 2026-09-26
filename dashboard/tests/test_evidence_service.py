from __future__ import annotations

from types import SimpleNamespace

from dashboard.services.evidence import EvidenceService


class FakeSource:
    def __init__(self):
        self.events = (
            SimpleNamespace(
                event_id="event-001",
                tenant_id="tenant-a",
                instance_name="web-a",
            ),
        )

        self.records = (
            SimpleNamespace(
                evidence_id="record-001",
                tenant_id="tenant-a",
                instance_name="web-a",
            ),
        )

        self.event_calls = []
        self.record_calls = []

    def fetch_events(self, *, tenant_id=None, instance_name=None, limit=100):
        self.event_calls.append(
            {
                "tenant_id": tenant_id,
                "instance_name": instance_name,
                "limit": limit,
            }
        )
        return self.events

    def fetch_records(self, *, tenant_id=None, instance_name=None, limit=100):
        self.record_calls.append(
            {
                "tenant_id": tenant_id,
                "instance_name": instance_name,
                "limit": limit,
            }
        )
        return self.records

    def fetch_event(self, evidence_id):
        if evidence_id == "event-001":
            return self.events[0]
        return None

    def fetch_record(self, evidence_id):
        if evidence_id == "record-001":
            return self.records[0]
        return None


def test_list_evidence_combines_events_and_records():
    source = FakeSource()

    service = EvidenceService(
        source=source,
        evidence_limit=50,
    )

    result = service.list_evidence(
        tenant_id="tenant-a",
        instance_name="web-a",
        limit=25,
    )

    assert len(result) == 2
    assert result[0].event_id == "event-001"
    assert result[1].evidence_id == "record-001"

    assert source.event_calls == [
        {
            "tenant_id": "tenant-a",
            "instance_name": "web-a",
            "limit": 25,
        }
    ]

    assert source.record_calls == [
        {
            "tenant_id": "tenant-a",
            "instance_name": "web-a",
            "limit": 25,
        }
    ]


def test_get_evidence_returns_event_first():
    source = FakeSource()

    service = EvidenceService(
        source=source,
        evidence_limit=50,
    )

    result = service.get_evidence("event-001")

    assert result is not None
    assert result.event_id == "event-001"


def test_get_evidence_falls_back_to_record():
    source = FakeSource()

    service = EvidenceService(
        source=source,
        evidence_limit=50,
    )

    result = service.get_evidence("record-001")

    assert result is not None
    assert result.evidence_id == "record-001"


def test_get_evidence_returns_none_when_missing():
    source = FakeSource()

    service = EvidenceService(
        source=source,
        evidence_limit=50,
    )

    assert service.get_evidence("does-not-exist") is None