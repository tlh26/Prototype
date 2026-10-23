from unittest.mock import Mock, patch
from datetime import datetime, timezone
from types import SimpleNamespace

from django.conf import settings
from django.http import HttpResponse
from django.middleware.gzip import GZipMiddleware
from django.test import RequestFactory, SimpleTestCase

from dashboard.views import (
    _begin_source_read,
    _filter_correlation_findings,
)


class DashboardPerformanceTests(SimpleTestCase):
    def test_begin_source_read_does_not_open_a_separate_health_check(self):
        source = Mock()

        with patch(
            "dashboard.views.build_correlation_source",
            return_value=source,
        ):
            self.assertIs(_begin_source_read(), source)

        source.begin_read.assert_called_once_with()
        source.check_central.assert_not_called()

    def test_gzip_middleware_compresses_large_responses(self):
        self.assertIn(
            "django.middleware.gzip.GZipMiddleware",
            settings.MIDDLEWARE,
        )
        request = RequestFactory().get(
            "/",
            HTTP_ACCEPT_ENCODING="gzip",
        )
        middleware = GZipMiddleware(
            lambda _request: HttpResponse("dashboard response " * 100)
        )

        response = middleware(request)

        self.assertEqual(response["Content-Encoding"], "gzip")


class CorrelationFilterTests(SimpleTestCase):
    def setUp(self):
        self.findings = (
            SimpleNamespace(
                cross_tenant=False,
                policy_allowed=True,
                event_start=datetime(2026, 1, 2, 10, tzinfo=timezone.utc),
                event_end=datetime(2026, 1, 2, 11, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                cross_tenant=True,
                policy_allowed=True,
                event_start=datetime(2026, 1, 3, 10, tzinfo=timezone.utc),
                event_end=datetime(2026, 1, 4, 11, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                cross_tenant=True,
                policy_allowed=False,
                event_start=datetime(2026, 1, 3, 10, tzinfo=timezone.utc),
                event_end=datetime(2026, 1, 4, 11, tzinfo=timezone.utc),
            ),
        )

    def test_filters_authorisation_basis_and_inclusive_event_date_range(self):
        findings, error = _filter_correlation_findings(
            self.findings,
            scope="cross_tenant",
            authorization_basis="cross_tenant",
            timestamp_from="2026-01-04",
            timestamp_to="2026-01-04",
        )

        self.assertEqual(findings, (self.findings[1],))
        self.assertEqual(error, "")

    def test_invalid_date_range_returns_no_findings_and_an_error(self):
        findings, error = _filter_correlation_findings(
            self.findings,
            scope="",
            authorization_basis="",
            timestamp_from="2026-01-05",
            timestamp_to="2026-01-04",
        )

        self.assertEqual(findings, ())
        self.assertTrue(error)
