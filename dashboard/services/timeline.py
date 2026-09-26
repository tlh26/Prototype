from __future__ import annotations

from correlation.timeline import EvidenceTimeline
from dashboard.services.correlation import CorrelationService


class TimelineService:
    def __init__(
        self,
        *,
        correlation_service: CorrelationService,
        timeline: EvidenceTimeline | None = None,
    ) -> None:
        self.correlation_service = correlation_service
        self.timeline = timeline or EvidenceTimeline()

    def build(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ):
        result = self.correlation_service.correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )

        return self.timeline.build(list(result.evidence))