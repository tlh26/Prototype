# dashboard/services/overview.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dashboard.services.correlation import CorrelationService
from dashboard.services.correlationPresentation import (
    CorrelationPresentationAdapter,
)
from dashboard.services.tenants import TenantService


@dataclass(frozen=True)
class OverviewSummary:
    tenant_count: int
    evidence_count: int
    finding_count: int
    entity_count: int
    relationship_count: int
    tenants: tuple

    candidate_count: int = 0
    evaluated_candidate_count: int = 0
    policy_denied_count: int = 0
    causal_relationship_count: int = 0
    duration_seconds: float = 0.0
    correlation_presentation: dict[str, Any] | None = None


class OverviewService:
    def __init__(
        self,
        *,
        tenant_service: TenantService,
        correlation_service: CorrelationService,
        evidence_limit: int = 100,
        presentation_adapter: (
            CorrelationPresentationAdapter | None
        ) = None,
    ) -> None:
        self.tenant_service = tenant_service
        self.correlation_service = correlation_service
        self.evidence_limit = evidence_limit
        self.presentation_adapter = (
            presentation_adapter
            or CorrelationPresentationAdapter()
        )

    def build(self) -> OverviewSummary:
        tenants = self.tenant_service.list_tenants()

        result = self.correlation_service.correlate(
            limit=self.evidence_limit,
        )

        presentation = self.presentation_adapter.adapt(result)
        metrics = presentation["metrics"]

        return OverviewSummary(
            tenant_count=len(tenants),
            evidence_count=metrics["evidence_count"],
            finding_count=metrics["finding_count"],
            entity_count=metrics["entity_count"],
            relationship_count=metrics["relationship_count"],
            tenants=tenants,
            candidate_count=metrics["candidate_count"],
            evaluated_candidate_count=(
                metrics["evaluated_candidate_count"]
            ),
            policy_denied_count=metrics["policy_denied_count"],
            causal_relationship_count=(
                metrics["causal_relationship_count"]
            ),
            duration_seconds=metrics["duration_seconds"],
            correlation_presentation=presentation,
        )
