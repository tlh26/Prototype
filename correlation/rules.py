# correlation/rules.py

from __future__ import annotations

from datetime import timedelta

from correlation.models import CanonicalEvidence
from correlation.correlationFinding import (
    CorrelationFinding,
    FindingSeverity,
)


class SameTenantTemporalRule:
    """
    Correlates evidence belonging to the same tenant when the events occur
    within a configured temporal window.
    """

    rule_id = "same-tenant-temporal"
    rule_version = "1.0"

    def __init__(self, window_seconds: int = 10):
        self.window = timedelta(seconds=window_seconds)

    def evaluate(
        self,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> CorrelationFinding | None:

        if first.evidence_id == second.evidence_id:
            return None

        if first.tenant_id is None:
            return None

        if second.tenant_id is None:
            return None

        # Critical tenant-isolation condition.
        if first.tenant_id != second.tenant_id:
            return None

        if first.event_timestamp is None:
            return None

        if second.event_timestamp is None:
            return None

        delta = abs(second.event_timestamp - first.event_timestamp)

        if delta > self.window:
            return None

        first_id, second_id = sorted([first.evidence_id, second.evidence_id])

        finding_id = f"{self.rule_id}:" f"{first_id}:" f"{second_id}"

        timestamps = sorted(
            [
                first.event_timestamp,
                second.event_timestamp,
            ]
        )

        return CorrelationFinding(
            finding_id=finding_id,
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            title="Same-tenant temporally related evidence",
            description=(
                "Two evidence items from the same tenant occurred "
                "within the configured temporal correlation window."
            ),
            severity=FindingSeverity.INFO,
            tenant_id=first.tenant_id,
            evidence_ids=(first_id, second_id),
            first_timestamp=timestamps[0],
            last_timestamp=timestamps[1],
            attributes={
                "window_seconds": str(int(self.window.total_seconds())),
                "time_delta_seconds": str(delta.total_seconds()),
            },
            created_at=timestamps[1],
        )
