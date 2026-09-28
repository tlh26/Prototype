from __future__ import annotations

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


def _begin_source_read():
    """
    Reset the request-level Central/cache status.

    All dashboard services ultimately use the same cached
    PostgreSQLCorrelationSource instance.
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
            limit=100,
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

    try:
        result = build_correlation_service().correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=100,
        )
    except CentralEvidenceUnavailable:
        result = None

    context = {
        "result": result,
        "findings": (
            result.findings
            if result is not None
            else ()
        ),
        "tenant_id": tenant_id,
        "instance_name": instance_name,
        **_source_context(source),
    }

    return render(
        request,
        "dashboard/correlations.html",
        context,
    )