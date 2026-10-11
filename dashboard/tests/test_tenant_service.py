from __future__ import annotations

from types import SimpleNamespace

from dashboard.services.tenants import TenantService


class FakeSource:
    def __init__(self):
        self.events = (
            SimpleNamespace(
                event_id="event-a-1",
                tenant_id="tenant-a",
                instance_name="web-a",
            ),
            SimpleNamespace(
                event_id="event-a-2",
                tenant_id="tenant-a",
                instance_name="api-a",
            ),
            SimpleNamespace(
                event_id="event-b-1",
                tenant_id="tenant-b",
                instance_name="web-b",
            ),
        )

        self.records = (
            SimpleNamespace(
                evidence_id="record-a-1",
                tenant_id="tenant-a",
                instance_name="db-a",
            ),
            SimpleNamespace(
                evidence_id="record-b-1",
                tenant_id="tenant-b",
                instance_name="db-b",
            ),
        )

        self.event_calls = []
        self.record_calls = []

    def fetch_tenants(self):
        return (
            "tenant-a",
            "tenant-b",
        )

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

        items = self.events

        if tenant_id is not None:
            items = tuple(
                item
                for item in items
                if item.tenant_id == tenant_id
            )

        return items[:limit]

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

        items = self.records

        if tenant_id is not None:
            items = tuple(
                item
                for item in items
                if item.tenant_id == tenant_id
            )

        return items[:limit]


def test_list_tenants_returns_sorted_tenant_summaries():
    source = FakeSource()

    service = TenantService(
        source=source,
        evidence_limit=100,
    )

    tenants = service.list_tenants()

    assert [tenant.tenant_id for tenant in tenants] == [
        "tenant-a",
        "tenant-b",
    ]

    tenant_a = tenants[0]

    assert tenant_a.event_count == 2
    assert tenant_a.record_count == 1
    assert tenant_a.evidence_count == 3
    assert tenant_a.instances == (
        "api-a",
        "db-a",
        "web-a",
    )


def test_get_tenant_returns_matching_tenant():
    source = FakeSource()

    service = TenantService(
        source=source,
        evidence_limit=100,
    )

    tenant = service.get_tenant("tenant-b")

    assert tenant is not None
    assert tenant.tenant_id == "tenant-b"
    assert tenant.event_count == 1
    assert tenant.record_count == 1
    assert tenant.instances == (
        "db-b",
        "web-b",
    )


def test_get_tenant_returns_none_for_unknown_tenant():
    source = FakeSource()

    service = TenantService(
        source=source,
        evidence_limit=100,
    )

    assert service.get_tenant("tenant-z") is None


def test_list_tenants_does_not_depend_on_evidence_limit():
    source = FakeSource()

    service = TenantService(
        source=source,
        evidence_limit=1,
    )

    tenants = service.list_tenants()

    assert [tenant.tenant_id for tenant in tenants] == [
        "tenant-a",
        "tenant-b",
    ]