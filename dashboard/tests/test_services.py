from __future__ import annotations

from types import SimpleNamespace

from dashboard.services.correlation import CorrelationService


class FakeSource:
    def __init__(self):
        self.event_calls = []
        self.record_calls = []

    def fetch_events(
        self,
        *,
        tenant_id=None,
        instance_name=None,
        limit=100,
    ):
        self.event_calls.append(
            {
                "tenant_id": tenant_id,
                "instance_name": instance_name,
                "limit": limit,
            }
        )

        return (
            SimpleNamespace(event_id="event-001"),
        )

    def fetch_records(
        self,
        *,
        tenant_id=None,
        instance_name=None,
        limit=100,
    ):
        self.record_calls.append(
            {
                "tenant_id": tenant_id,
                "instance_name": instance_name,
                "limit": limit,
            }
        )

        return (
            SimpleNamespace(evidence_id="record-001"),
        )


class FakeEngine:
    def __init__(self):
        self.process_calls = []

    def process(self, evidence):
        self.process_calls.append(tuple(evidence))

        return SimpleNamespace(
            evidence=tuple(evidence),
            entities=(),
            relationships=(),
            findings=("finding-001",),
        )


def test_correlation_service_fetches_both_evidence_sources():
    source = FakeSource()
    engine = FakeEngine()

    service = CorrelationService(
        source=source,
        engine=engine,
        evidence_limit=50,
    )

    result = service.correlate(
        tenant_id="tenant-b",
        instance_name="web-b",
    )

    assert result.findings == ("finding-001",)

    assert source.event_calls == [
        {
            "tenant_id": "tenant-b",
            "instance_name": "web-b",
            "limit": 50,
        }
    ]

    assert source.record_calls == [
        {
            "tenant_id": "tenant-b",
            "instance_name": "web-b",
            "limit": 50,
        }
    ]

    assert len(engine.process_calls) == 1
    assert len(engine.process_calls[0]) == 2
