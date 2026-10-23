
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.core.paginator import Paginator
from django.shortcuts import render
from django.utils.dateparse import parse_date

from correlation.centralEvidence import CentralEvidenceUnavailable
from correlation.models import CorrelationContext, PrivacyMode
from correlation.privacy import PrivacyConfigurationError
from evidenceAgent.evidenceAgent.models import EvidenceEvent
from dashboard.services.factory import (
    build_correlation_service,
    build_correlation_source,
    build_evidence_service,
    build_overview_service,
    build_tenant_service,
    build_timeline_service,
)
from evidenceAgent.evidenceAgent.models import EventType


def _begin_source_read():
    """
    Reset request-level Central/cache status.

    All dashboard services ultimately use the same cached
    PostgreSQLCorrelationSource instance. The first actual data read checks
    Central availability and uses the last-known cache if needed.
    """
    source = build_correlation_source()
    source.begin_read()
    return source


def _source_context(source):
    """Return the common Central availability context used by templates."""
    return {
        "central_available": source.central_available,
        "using_last_known_data": source.using_last_known_data,
        "last_known_timestamp": source.last_known_timestamp,
    }


def index(request):
    source = _begin_source_read()

    try:
        overview = build_overview_service().build()
    except CentralEvidenceUnavailable:
        overview = None

    context = {
        "overview": overview,
        **_source_context(source),
    }

    return render(request, "dashboard/overview.html", context)


def tenants(request):
    source = _begin_source_read()

    try:
        tenant_summaries = build_tenant_service().list_tenants()
    except CentralEvidenceUnavailable:
        tenant_summaries = ()

    context = {
        "tenants": tenant_summaries,
        **_source_context(source),
    }

    return render(request, "dashboard/tenants.html", context)


def evidence(request):
    source = _begin_source_read()

    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None
    timestamp_from = request.GET.get("timestamp_from", "")
    timestamp_to = request.GET.get("timestamp_to", "")
    event_type = request.GET.get("event_type", "")
    event_source = request.GET.get("event_source", "")

    try:
        evidence_items = build_evidence_service().list_evidence(
            tenant_id=tenant_id,
            instance_name=instance_name,
        )
    except CentralEvidenceUnavailable:
        evidence_items = ()

    evidence_items = tuple(
        item
        for item in evidence_items
        if isinstance(getattr(item, "tenant_id", None), str)
        and item.tenant_id.strip()
        and (
            getattr(item, "timestamp", None)
            if getattr(item, "event_id", None)
            else getattr(item, "collected_at", None)
        )
    )

    context = {
        "evidence_items": evidence_items,
        "tenant_id": tenant_id,
        "instance_name": instance_name,
        "timestamp_from": timestamp_from,
        "timestamp_to": timestamp_to,
        "event_type": event_type,
        "event_source": event_source,
        "event_types": tuple(
            (item.value, item.value.replace("_", " ").title())
            for item in EventType
        ),
        **_source_context(source),
    }

    return render(request, "dashboard/evidence.html", context)


def evidence_detail(request, evidence_id: str):
    source = _begin_source_read()

    try:
        evidence_item = (
            build_evidence_service().get_evidence(evidence_id)
        )
    except CentralEvidenceUnavailable:
        evidence_item = None

    privacy_mode = PrivacyMode(
        getattr(settings, "CORRELATION_PRIVACY_MODE", "raw")
    )
    if evidence_item is not None and privacy_mode != PrivacyMode.RAW:
        private_fields: dict[str, Any] = {"raw_data": b""}
        if hasattr(evidence_item, "details"):
            private_fields["details"] = {}

        if isinstance(evidence_item, EvidenceEvent):
            evidence_item = evidence_item.model_copy(
                update=private_fields
            )
        else:
            evidence_item = SimpleNamespace(
                **{**vars(evidence_item), **private_fields}
            )

    context = {
        "evidence": evidence_item,
        "evidence_id": evidence_id,
        "show_raw_evidence": privacy_mode == PrivacyMode.RAW,
        "privacy_mode": privacy_mode.value,
        **_source_context(source),
    }

    return render(request, "dashboard/evidence_detail.html", context)


def timeline(request):
    source = _begin_source_read()

    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None

    try:
        entries = build_timeline_service().build(
            tenant_id=tenant_id,
            instance_name=instance_name,
        )
    except CentralEvidenceUnavailable:
        entries = ()

    context = {
        "entries": entries,
        "tenant_id": tenant_id,
        "instance_name": instance_name,
        **_source_context(source),
    }

    return render(request, "dashboard/timeline.html", context)


def _filter_correlation_findings(
    findings,
    *,
    scope,
    authorization_basis,
    timestamp_from,
    timestamp_to,
):
    """Filter permitted findings by scope, authorization basis, and dates."""
    from_date = parse_date(timestamp_from) if timestamp_from else None
    to_date = parse_date(timestamp_to) if timestamp_to else None

    invalid_filter = (
        (scope and scope not in {"same_tenant", "cross_tenant"})
        or (
            authorization_basis
            and authorization_basis not in {"same_tenant", "cross_tenant"}
        )
        or (timestamp_from and from_date is None)
        or (timestamp_to and to_date is None)
        or (from_date and to_date and from_date > to_date)
    )

    if invalid_filter:
        return (), "One or more filters are invalid. Please check your selections."

    filtered = []

    for finding in findings:
        # Only display findings approved by the correlation policy.
        if not finding.policy_allowed:
            continue

        if scope == "same_tenant" and finding.cross_tenant:
            continue

        if scope == "cross_tenant" and not finding.cross_tenant:
            continue

        if authorization_basis == "same_tenant" and finding.cross_tenant:
            continue

        if (
            authorization_basis == "cross_tenant"
            and not finding.cross_tenant
        ):
            continue

        event_start = finding.event_start
        event_end = finding.event_end

        if from_date or to_date:
            if event_start is None and event_end is None:
                continue

            start_date = (event_start or event_end).date()
            end_date = (event_end or event_start).date()

            if from_date and end_date < from_date:
                continue

            if to_date and start_date > to_date:
                continue

        filtered.append(finding)

    return tuple(filtered), ""


def correlations(request):
    source = _begin_source_read()

    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None
    scope = request.GET.get("scope", "")
    authorization_basis = request.GET.get("authorization_basis", "")
    timestamp_from = request.GET.get("timestamp_from", "")
    timestamp_to = request.GET.get("timestamp_to", "")

    # Bound the requested page size to prevent enormous responses.
    try:
        page_size = int(request.GET.get("page_size", 25))
    except (TypeError, ValueError):
        page_size = 25

    page_size = max(1, min(page_size, 50))

    result = None
    presentation = None
    findings_page = Paginator((), page_size).get_page(1)
    filter_error = ""
    filtered_finding_count = 0

    # Build the analysis context BEFORE calling the engine.
    # Cross-tenant analysis is denied by default.
    cross_tenant_enabled = getattr(
        settings,
        "CORRELATION_ENABLE_CROSS_TENANT",
        True,
    )

    allowed_pairs = getattr(
        settings,
        "CORRELATION_ALLOWED_TENANT_PAIRS",
        (),
    )

    cross_tenant_authorised = bool(
        cross_tenant_enabled and allowed_pairs
    )
    context_options = {}
    permitted_features = getattr(
        settings,
        "CORRELATION_PERMITTED_FEATURE_TYPES",
        None,
    )
    if permitted_features is not None:
        context_options["permitted_feature_types"] = tuple(
            permitted_features
        )

    analysis_context = CorrelationContext(
        analysis_id=f"dashboard-{uuid4()}",
        allow_cross_tenant=cross_tenant_authorised,
        allowed_tenant_pairs=(
            tuple(allowed_pairs)
            if cross_tenant_authorised
            else ()
        ),
        privacy_mode=PrivacyMode(
            getattr(settings, "CORRELATION_PRIVACY_MODE", "raw")
        ),
        **context_options,
    )

    try:
        service = build_correlation_service()

        # Run the authoritative engine once for this request.
        # Cross-tenant access remains explicitly disabled unless configured.
        result = service.correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
            context=analysis_context,
        )

        filtered_findings, filter_error = _filter_correlation_findings(
            result.findings,
            scope=scope,
            authorization_basis=authorization_basis,
            timestamp_from=timestamp_from,
            timestamp_to=timestamp_to,
        )

        filtered_finding_count = len(filtered_findings)

        # Paginate before building the dashboard presentation.
        paginator = Paginator(filtered_findings, page_size)
        findings_page = paginator.get_page(request.GET.get("page", 1))

        # Adapt only the visible findings and a bounded graph preview.
        presentation = service.presentation_adapter.adapt(
            result,
            findings=findings_page.object_list,
            graph_finding_limit=12,
            graph_edge_limit=40,
        )

    except CentralEvidenceUnavailable:
        result = None
        presentation = None
        findings_page = Paginator((), page_size).get_page(1)
    except PrivacyConfigurationError as exc:
        result = None
        presentation = None
        findings_page = Paginator((), page_size).get_page(1)
        filter_error = str(exc)

    return render(
        request,
        "dashboard/correlations.html",
        {
            # Keep the result for summary fields, but do not loop over
            # result.findings in the template.
            "result": result,
            "presentation": presentation,
            "findings": (
                findings_page.object_list
                if presentation is None
                else presentation["findings"]
            ),
            "findings_page": findings_page,
            "page_obj": findings_page,
            "paginator": findings_page.paginator,
            "page_size": page_size,
            "tenant_id": tenant_id,
            "instance_name": instance_name,
            "scope": scope,
            "authorization_basis": authorization_basis,
            "timestamp_from": timestamp_from,
            "timestamp_to": timestamp_to,
            "filter_error": filter_error,
            "filtered_finding_count": filtered_finding_count,
            **_source_context(source),
        },
    )
