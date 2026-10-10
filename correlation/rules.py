# correlation/rules.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from correlation.models import (
    CanonicalEvidence,
    CorrelationCandidate,
    CorrelationFeature,
    CorrelationFinding,
    CorrelationScore,
    EvidenceReference,
    FindingSeverity,
    FindingStatus,
)


class SameTenantTemporalRule:
    """
    Baseline deterministic rule.

    This rule is retained as a baseline comparator for experiments. The
    primary engine uses candidate generation + weighted scoring rather than
    treating this rule as the complete correlation mechanism.

    Legacy contract:
        - returns a CorrelationFinding when the two events satisfy the rule
        - returns None when they do not
    """

    rule_id = "same-tenant-temporal"
    version = "1.0"

    def __init__(
        self,
        temporal_window_seconds: float = 10.0,
        *,
        window_seconds: float | None = None,
    ) -> None:
        if window_seconds is not None:
            temporal_window_seconds = window_seconds

        if temporal_window_seconds < 0:
            raise ValueError(
                "temporal_window_seconds must be >= 0"
            )

        self.temporal_window_seconds = temporal_window_seconds

    def evaluate(
        self,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> CorrelationFinding | None:
        # ------------------------------------------------------------------
        # 1. Tenant boundary
        # ------------------------------------------------------------------
        # This legacy baseline deliberately operates only within one tenant.
        if first.tenant_id != second.tenant_id:
            return None

        # ------------------------------------------------------------------
        # 2. Temporal prerequisites
        # ------------------------------------------------------------------
        # A temporal rule cannot operate without trustworthy event times.
        if (
            first.event_timestamp is None
            or second.event_timestamp is None
        ):
            return None

        # ------------------------------------------------------------------
        # 3. Temporal relationship
        # ------------------------------------------------------------------
        delta = abs(
            (
                first.event_timestamp
                - second.event_timestamp
            ).total_seconds()
        )

        if delta > self.temporal_window_seconds:
            return None

        # ------------------------------------------------------------------
        # 4. Deterministic identifiers
        # ------------------------------------------------------------------
        evidence_ids = (
            first.evidence_id,
            second.evidence_id,
        )

        candidate_id = (
            f"{self.rule_id}:"
            f"{first.evidence_id}:"
            f"{second.evidence_id}"
        )

        finding_id = (
            f"{self.rule_id}:"
            f"{first.evidence_id}:"
            f"{second.evidence_id}"
        )

        # ------------------------------------------------------------------
        # 5. Explainable baseline feature
        # ------------------------------------------------------------------
        #
        # CorrelationFeature requires:
        #   feature_name
        #   value
        #   weight
        #   contribution = value * weight
        #
        # For this deterministic baseline, a successful match is represented
        # as a full-strength temporal feature.
        feature = CorrelationFeature(
            feature_name="temporal",
            value=1.0,
            weight=1.0,
            contribution=1.0,
            explanation=(
                f"Events occurred within the "
                f"{self.temporal_window_seconds:g}-second "
                f"baseline temporal window "
                f"(delta={delta:g}s)."
            ),
            evidence_ids=evidence_ids,
            attributes_used=(
                "event_timestamp",
            ),
            metadata={
                "time_delta_seconds": delta,
                "window_seconds": (
                    self.temporal_window_seconds
                ),
            },
        )

        # ------------------------------------------------------------------
        # 6. Explainable score
        # ------------------------------------------------------------------
        score = CorrelationScore(
            value=1.0,
            threshold=1.0,
            passed=True,
            features=(feature,),
            scoring_method="legacy_same_tenant_temporal_v1",
            weight_sum=1.0,
            valid_feature_count=1,
            explanation=(
                "Baseline same-tenant temporal rule matched."
            ),
            metadata={
                "rule_id": self.rule_id,
                "rule_version": self.version,
            },
        )

        # ------------------------------------------------------------------
        # 7. Finding
        # ------------------------------------------------------------------
        return CorrelationFinding(
            finding_id=finding_id,
            created_at=datetime.now(timezone.utc),
            status=FindingStatus.CONFIRMED,
            severity=FindingSeverity.INFO,

            candidate_id=candidate_id,
            analysis_id=(
                f"legacy:{self.rule_id}"
            ),

            tenant_ids=(
                first.tenant_id,
            ),
            cross_tenant=False,

            evidence_ids=evidence_ids,

            evidence_references=(
                EvidenceReference(
                    evidence_id=first.evidence_id,
                    source_table="evidence",
                    sha256=first.sha256,
                ),
                EvidenceReference(
                    evidence_id=second.evidence_id,
                    source_table="evidence",
                    sha256=second.sha256,
                ),
            ),

            provenance=(),

            score=score,

            explanation=(
                "Baseline same-tenant temporal correlation "
                f"matched events {first.evidence_id} and "
                f"{second.evidence_id}."
            ),

            reason_codes=(
                self.rule_id,
            ),

            entity_ids=(),
            relationship_ids=(),
            graph_edge_id=None,

            policy_id="tenant-correlation-policy",
            policy_allowed=True,
            policy_reason=(
                "Same-tenant correlation is permitted."
            ),

            event_start=min(
                first.event_timestamp,
                second.event_timestamp,
            ),
            event_end=max(
                first.event_timestamp,
                second.event_timestamp,
            ),

            # CorrelationFinding restricts this field to the defined
            # privacy modes. The legacy baseline operates on the canonical
            # evidence representation, so "raw" is used explicitly.
            privacy_mode="raw",

            engine_version=(
                f"legacy-rule:{self.version}"
            ),
            configuration_version="legacy",

            metadata={
                "rule_id": self.rule_id,
                "rule_version": self.version,
                "time_delta_seconds": delta,
                "temporal_window_seconds": (
                    self.temporal_window_seconds
                ),
            },
        )

    def evaluate_candidate(
        self,
        candidate: CorrelationCandidate,
        evidence_by_id: dict[str, CanonicalEvidence],
    ) -> bool:
        if len(candidate.evidence_ids) != 2:
            return False

        first = evidence_by_id[
            candidate.evidence_ids[0]
        ]

        second = evidence_by_id[
            candidate.evidence_ids[1]
        ]

        return (
            self.evaluate(first, second)
            is not None
        )

    def describe(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "temporal_window_seconds": (
                self.temporal_window_seconds
            ),
            "type": "baseline",
        }
