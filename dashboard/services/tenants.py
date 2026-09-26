from __future__ import annotations

from dataclasses import dataclass

from correlation.centralEvidence import PostgreSQLCorrelationSource


@dataclass(frozen=True)
class TenantSummary:
    tenant_id: str
    event_count: int
    record_count: int
    evidence_count: int
    instances: tuple[str, ...]


class TenantService:
    def __init__(
        self,
        *,
        source: PostgreSQLCorrelationSource,
        evidence_limit: int = 100,
    ) -> None:
        self.source = source
        self.evidence_limit = evidence_limit

    def list_tenants(self) -> tuple[TenantSummary, ...]:
        tenant_ids = self.source.fetch_tenants()

        summaries = []

        for tenant_id in tenant_ids:
            tenant_events = self.source.fetch_events(
                tenant_id=tenant_id,
                limit=self.evidence_limit,
            )

            tenant_records = self.source.fetch_records(
                tenant_id=tenant_id,
                limit=self.evidence_limit,
            )

            instances = {
                instance_name
                for item in (*tenant_events, *tenant_records)
                if (instance_name := getattr(item, "instance_name", None))
            }

            summaries.append(
                TenantSummary(
                    tenant_id=tenant_id,
                    event_count=len(tenant_events),
                    record_count=len(tenant_records),
                    evidence_count=(
                        len(tenant_events) + len(tenant_records)
                    ),
                    instances=tuple(sorted(instances)),
                )
            )

        return tuple(summaries)

    def get_tenant(
        self,
        tenant_id: str,
    ) -> TenantSummary | None:
        for tenant in self.list_tenants():
            if tenant.tenant_id == tenant_id:
                return tenant

        return None