from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import RequestFactory, SimpleTestCase

from dashboard.views import evidence
from evidenceAgent.evidenceAgent.models import EventType


class EvidenceFilterPageTests(SimpleTestCase):
    def test_filter_values_and_event_metadata_are_rendered(self):
        event = SimpleNamespace(
            event_id="event-001",
            timestamp=datetime(2026, 1, 2, 12, 30, tzinfo=timezone.utc),
            event_type=EventType.LOGIN_SUCCESS,
            source="authentication",
            tenant_id="tenant-a",
            instance_name="web-a",
        )
        source = SimpleNamespace(
            central_available=True,
            using_last_known_data=False,
            last_known_timestamp=None,
        )
        service = Mock()
        service.list_evidence.return_value = (event,)
        request = RequestFactory().get(
            "/evidence/",
            {
                "timestamp_from": "2026-01-02T12:00",
                "timestamp_to": "2026-01-02T13:00",
                "event_type": EventType.LOGIN_SUCCESS.value,
                "event_source": "auth",
            },
        )

        with (
            patch("dashboard.views._begin_source_read", return_value=source),
            patch("dashboard.views.build_evidence_service", return_value=service),
        ):
            response = evidence(request)

        self.assertContains(response, 'value="2026-01-02T12:00"')
        self.assertContains(response, 'value="2026-01-02T13:00"')
        self.assertContains(response, 'data-event-type="LOGIN_SUCCESS"')
        self.assertContains(response, 'data-source="authentication"')
        self.assertContains(response, 'data-timestamp="2026-01-02T12:30:00+00:00"')

    def test_only_evidence_with_tenant_and_event_timestamp_is_displayed(self):
        valid_event = SimpleNamespace(
            event_id="event-valid",
            timestamp=datetime(2026, 1, 2, 12, 30, tzinfo=timezone.utc),
            event_type=EventType.LOGIN_SUCCESS,
            tenant_id="tenant-a",
            instance_name="web-a",
            source="authentication",
        )
        missing_tenant = SimpleNamespace(
            event_id="event-no-tenant",
            timestamp=datetime(2026, 1, 2, 12, 30, tzinfo=timezone.utc),
            event_type=EventType.LOGIN_SUCCESS,
            tenant_id=" ",
            instance_name="web-a",
            source="authentication",
        )
        missing_timestamp = SimpleNamespace(
            event_id="event-no-timestamp",
            timestamp=None,
            event_type=EventType.LOGIN_SUCCESS,
            tenant_id="tenant-a",
            instance_name="web-a",
            source="authentication",
        )
        valid_record = SimpleNamespace(
            evidence_id="record-valid",
            collected_at=datetime(2026, 1, 2, 12, 30, tzinfo=timezone.utc),
            evidence_type="HOST",
            tenant_id="tenant-a",
            instance_name="web-a",
            source="forensic",
        )
        source = SimpleNamespace(
            central_available=True,
            using_last_known_data=False,
            last_known_timestamp=None,
        )
        service = Mock()
        service.list_evidence.return_value = (
            valid_event,
            missing_tenant,
            missing_timestamp,
            valid_record,
        )
        request = RequestFactory().get("/evidence/")

        with (
            patch("dashboard.views._begin_source_read", return_value=source),
            patch("dashboard.views.build_evidence_service", return_value=service),
        ):
            response = evidence(request)

        self.assertContains(response, "event-valid")
        self.assertContains(response, "record-valid")
        self.assertNotContains(response, "event-no-tenant")
        self.assertNotContains(response, "event-no-timestamp")
