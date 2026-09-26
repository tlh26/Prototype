from __future__ import annotations

from django.http import Http404
from django.shortcuts import render

from dashboard.services.factory import (
    build_correlation_service,
    build_evidence_service,
)


def index(request):
    """
    Dashboard foundation / D1 smoke view.
    """
    return render(
        request,
        "dashboard/overview.html",
    )


def correlations(request):
    """
    Display correlation findings produced by the authoritative
    CorrelationEngine.
    """
    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None

    service = build_correlation_service()

    result = service.correlate(
        tenant_id=tenant_id,
        instance_name=instance_name,
        limit=100,
    )

    return render(
        request,
        "dashboard/correlations.html",
        {
            "result": result,
            "findings": result.findings,
            "tenant_id": tenant_id,
            "instance_name": instance_name,
        },
    )


def evidence(request):
    """
    Display authoritative evidence from Central PostgreSQL.
    """
    tenant_id = request.GET.get("tenant_id") or None
    instance_name = request.GET.get("instance_name") or None

    service = build_evidence_service()

    evidence_items = service.list_evidence(
        tenant_id=tenant_id,
        instance_name=instance_name,
        limit=100,
    )

    return render(
        request,
        "dashboard/evidence.html",
        {
            "evidence_items": evidence_items,
            "tenant_id": tenant_id,
            "instance_name": instance_name,
        },
    )


def evidence_detail(request, evidence_id: str):
    """
    Display one authoritative evidence event or forensic record.
    """
    service = build_evidence_service()

    evidence_item = service.get_evidence(evidence_id)

    if evidence_item is None:
        raise Http404("Evidence item not found.")

    return render(
        request,
        "dashboard/evidence_detail.html",
        {
            "evidence": evidence_item,
        },
    )