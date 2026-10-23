from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import RequestFactory, SimpleTestCase, override_settings
from django.template.loader import render_to_string

from correlation.models import PrivacyMode
from correlation.privacy import PrivacyConfigurationError
from dashboard.views import correlations, evidence_detail


class CorrelationPrivacyViewTests(SimpleTestCase):
    @override_settings(
        CORRELATION_ENABLE_CROSS_TENANT=False,
        CORRELATION_ALLOWED_TENANT_PAIRS=(("tenant-a", "tenant-b"),),
        CORRELATION_PRIVACY_MODE="pseudonymised",
        CORRELATION_PERMITTED_FEATURE_TYPES=None,
    )
    def test_privacy_mode_is_applied_without_cross_tenant_authorisation(self):
        source = SimpleNamespace(
            central_available=True,
            using_last_known_data=False,
            last_known_timestamp=None,
        )
        service = Mock()
        service.correlate.side_effect = PrivacyConfigurationError(
            "Set a secure key."
        )

        with (
            patch(
                "dashboard.views._begin_source_read",
                return_value=source,
            ),
            patch("dashboard.views._source_context", return_value={}),
            patch(
                "dashboard.views.build_correlation_service",
                return_value=service,
            ),
            patch(
                "dashboard.views.render",
                side_effect=lambda *args: args[2],
            ),
        ):
            response_context = correlations(
                RequestFactory().get("/correlations/")
            )

        analysis_context = service.correlate.call_args.kwargs["context"]
        assert analysis_context.privacy_mode == PrivacyMode.PSEUDONYMISED
        assert analysis_context.allow_cross_tenant is False
        assert analysis_context.allowed_tenant_pairs == ()
        assert response_context["filter_error"] == "Set a secure key."


class EvidenceDetailPrivacyViewTests(SimpleTestCase):
    def test_pseudonymised_mode_hides_raw_evidence(self):
        source = SimpleNamespace(
            central_available=True,
            using_last_known_data=False,
            last_known_timestamp=None,
        )
        service = Mock()
        service.get_evidence.return_value = SimpleNamespace(
            event_id="test-id",
            raw_data=b"sensitive raw line",
            details={"raw_line": "sensitive raw line"},
        )

        with (
            override_settings(CORRELATION_PRIVACY_MODE="pseudonymised"),
            patch(
                "dashboard.views._begin_source_read",
                return_value=source,
            ),
            patch("dashboard.views._source_context", return_value={}),
            patch(
                "dashboard.views.build_evidence_service",
                return_value=service,
            ),
            patch(
                "dashboard.views.render",
                side_effect=lambda *args: args[2],
            ),
        ):
            response_context = evidence_detail(
                RequestFactory().get("/evidence/test-id/"),
                "test-id",
            )

        assert response_context["show_raw_evidence"] is False
        assert response_context["privacy_mode"] == "pseudonymised"
        assert response_context["evidence"].raw_data == b""
        assert response_context["evidence"].details == {}
        rendered_page = render_to_string(
            "dashboard/evidence_detail.html",
            response_context,
        )
        assert "sensitive raw line" not in rendered_page
        assert "Event details are hidden" in rendered_page

    def test_raw_mode_keeps_raw_evidence_visible(self):
        source = SimpleNamespace(
            central_available=True,
            using_last_known_data=False,
            last_known_timestamp=None,
        )
        service = Mock()
        service.get_evidence.return_value = SimpleNamespace(
            raw_data=b"raw line"
        )

        with (
            override_settings(CORRELATION_PRIVACY_MODE="raw"),
            patch(
                "dashboard.views._begin_source_read",
                return_value=source,
            ),
            patch("dashboard.views._source_context", return_value={}),
            patch(
                "dashboard.views.build_evidence_service",
                return_value=service,
            ),
            patch(
                "dashboard.views.render",
                side_effect=lambda *args: args[2],
            ),
        ):
            response_context = evidence_detail(
                RequestFactory().get("/evidence/test-id/"),
                "test-id",
            )

        assert response_context["show_raw_evidence"] is True
