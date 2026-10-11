# correlation.findings.py

"""Generate explainable findings from accepted correlation results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from correlation.models import (
    CausalLink,
    CorrelationCandidate,
    CorrelationFinding,
    CorrelationScore,
    CorrelationContext,
    EvidenceRelationship,
    FindingSeverity,
    FindingStatus,
)


class FindingGenerator:
    """Create stable, provenance-preserving correlation findings."""

    VERSION = "1.0"

    def generate(
        self,
        *,
        candidate: CorrelationCandidate,
        score: CorrelationScore,
        context: CorrelationContext,
        relationships: Iterable[EvidenceRelationship],
        policy_id: str,
        policy_reason: str,
        causal_relationships: tuple[CausalLink, ...] = (),
        causal_explanation: str = "",
        causal_metadata: dict[str, Any] | None = None,
    ) -> CorrelationFinding:
        if not score.passed:
            raise ValueError(
                "Cannot generate a finding for a candidate that failed scoring."
            )

        relationship_ids = tuple(sorted({
            relationship.relationship_id
            for relationship in relationships
            if set(relationship.evidence_ids).intersection(
                candidate.evidence_ids
            )
        }))

        feature_explanations = "; ".join(
            feature.explanation for feature in score.features
        )

        explanation = (
            f"Candidate {candidate.candidate_id} correlated with "
            f"score {score.value:.4f}. {score.explanation}"
        )

        if feature_explanations:
            explanation += f" Feature details: {feature_explanations}"

        if causal_explanation:
            explanation += f" Causal assessment: {causal_explanation}"

        causal_ids = tuple(sorted({
            link.relationship_id for link in causal_relationships
        }))

        return CorrelationFinding(
            finding_id=(
                f"finding:{context.analysis_id}:{candidate.candidate_id}"
            ),
            created_at=datetime.now(timezone.utc),
            status=FindingStatus.CONFIRMED,
            severity=FindingSeverity.INFO,
            candidate_id=candidate.candidate_id,
            analysis_id=context.analysis_id,
            tenant_ids=candidate.tenant_ids,
            cross_tenant=candidate.cross_tenant,
            evidence_ids=candidate.evidence_ids,
            evidence_references=candidate.evidence_references,
            provenance=candidate.provenance,
            score=score,
            explanation=explanation,
            reason_codes=candidate.generation_reasons,
            entity_ids=candidate.shared_entity_ids,
            relationship_ids=relationship_ids,
            causal_relationship_ids=causal_ids,
            causal_relationships=causal_relationships,
            graph_edge_id=f"edge:correlated:{candidate.candidate_id}",
            policy_id=policy_id,
            policy_allowed=True,
            policy_reason=policy_reason,
            event_start=candidate.earliest_timestamp,
            event_end=candidate.latest_timestamp,
            privacy_mode=context.privacy_mode,
            engine_version="3.3",
            configuration_version=context.configuration_version,
            metadata={
                "blocking_keys": candidate.blocking_keys,
                "time_delta_seconds": candidate.time_delta_seconds,
                "shared_resources": candidate.shared_resources,
                "causal_reasoning": causal_metadata or {},
                "finding_generator_version": self.VERSION,
            },
        )

    @staticmethod
    def deduplicate(
        findings: Iterable[CorrelationFinding],
    ) -> tuple[CorrelationFinding, ...]:
        """Return one finding per ID in deterministic order."""
        unique: dict[str, CorrelationFinding] = {}

        for finding in findings:
            unique.setdefault(finding.finding_id, finding)

        return tuple(unique[key] for key in sorted(unique))
