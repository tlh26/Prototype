from __future__ import annotations

from dataclasses import dataclass

from dashboard.services.correlation import CorrelationService
from dashboard.services.tenants import TenantService


@dataclass(frozen=True)
class OverviewSummary:
    tenant_count: int
    evidence_count: int
    finding_count: int
    entity_count: int
    relationship_count: int
    tenants: tuple


class OverviewService:
    def __init__(
        self,
        *,
        tenant_service: TenantService,
        correlation_service: CorrelationService,
        evidence_limit: int = 100,
    ) -> None:
        self.tenant_service = tenant_service
        self.correlation_service = correlation_service
        self.evidence_limit = evidence_limit

    def build(self) -> OverviewSummary:
        tenants = self.tenant_service.list_tenants()

        result = self.correlation_service.correlate(
            limit=self.evidence_limit,
        )

        return OverviewSummary(
            tenant_count=len(tenants),
            evidence_count=len(result.evidence),
            finding_count=len(result.findings),
            entity_count=len(result.entities),
            relationship_count=len(result.relationships),
            tenants=tenants,
        )