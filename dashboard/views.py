# dashboard/views.py
from __future__ import annotations

from django.shortcuts import render
from django.http import Http404
from django.shortcuts import render
from correlation.centralEvidence import (
    CentralEvidenceUnavailable,
)
from dashboard.services.factory import (
    build_correlation_service,
    build_correlation_source,
    build_evidence_service,
    build_tenant_service,
    build_timeline_service,
    build_overview_service
)
from correlation.centralEvidence import PostgreSQLCorrelationSource
from correlation.engine import CorrelationEngine
from evidenceAgent.evidenceAgent.models import EventType

from dashboard.services.correlation import CorrelationService
from dashboard.services.correlationPresentation import (
    CorrelationPresentationAdapter,
)
from django.core.paginator import Paginator
from django.shortcuts import render


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
    """
    Return the common Central availability context used by templates.
    """
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

    return render(
        request,
        "dashboard/overview.html",
        context,
    )



def tenants(request):
    source = _begin_source_read()

    try:
        tenant_summaries = (
            build_tenant_service().list_tenants()
        )
    except CentralEvidenceUnavailable:
        tenant_summaries = ()

    context = {
        "tenants": tenant_summaries,
        **_source_context(source),
    }

    return render(
        request,
        "dashboard/tenants.html",
        context,
    )


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

    return render(
        request,
        "dashboard/evidence.html",
        context,
    )


def evidence_detail(
    request,
    evidence_id: str,
):
    source = _begin_source_read()

    try:
        evidence = (
            build_evidence_service()
            .get_evidence(evidence_id)
        )
    except CentralEvidenceUnavailable:
        evidence = None

    context = {
        "evidence": evidence,
        "evidence_id": evidence_id,
        **_source_context(source),
    }

    return render(
        request,
        "dashboard/evidence_detail.html",
        context,
    )


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

    return render(
        request,
        "dashboard/timeline.html",
        context,
    )



def correlations(request):
    source = _begin_source_read()

    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None

    # Bound the requested page size to prevent enormous responses.
    try:
        page_size = int(request.GET.get("page_size", 25))
    except (TypeError, ValueError):
        page_size = 25

    page_size = max(1, min(page_size, 50))

    result = None
    presentation = None
    findings_page = Paginator((), page_size).get_page(1)

    try:
        service = build_correlation_service()

        # Run the authoritative engine once for this request.
        result = service.correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
        )

        # Paginate before building the dashboard presentation.
        paginator = Paginator(result.findings, page_size)
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

    return render(
        request,
        "dashboard/correlations.html",
        {
            # Keep the result for summary fields, but never loop over
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
            **_source_context(source),
        },
    )