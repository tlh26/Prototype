# correlation/engine.py

"""Tenant-aware, privacy-controlled multi-stage evidence correlation."""

from __future__ import annotations

from copy import copy
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Iterable
from time import perf_counter


from correlation.attributes import AttributeExtractor
from correlation.candidates import CandidateGenerator
from correlation.causal import CausalReasoner
from correlation.entities import EntityExtractor
from correlation.graph import EvidenceGraphBuilder
from correlation.models import (
    CanonicalEvidence,
    CausalLink,
    CorrelationCandidate,
    CorrelationContext,
    CorrelationFinding,
    CorrelationResult,
    EvidenceEntity,
    EvidenceRelationship,
    FindingSeverity,
    FindingStatus,
)
from correlation.normaliser import EvidenceNormaliser
from correlation.policy import CrossTenantPolicy
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule
from correlation.scoring import CorrelationScorer


class CorrelationEngine:
    """Run policy-controlled correlation, causal reasoning, and graph building.

    A causal relationship supplements a scored correlation finding. The
    absence of a causal link does not invalidate an otherwise accepted
    correlation candidate.
    """

    engine_version = "3.2"

    def __init__(
        self,
        normaliser: EvidenceNormaliser | None = None,
        attribute_extractor: AttributeExtractor | None = None,
        entity_mapper: EntityExtractor | None = None,
        relationship_mapper: RelationshipMapper | None = None,
        rules: Iterable[Any] | None = None,
        candidate_generator: CandidateGenerator | None = None,
        scorer: CorrelationScorer | None = None,
        policy: CrossTenantPolicy | None = None,
        causal_reasoner: CausalReasoner | None = None,
        graph_builder: EvidenceGraphBuilder | None = None,
    ) -> None:
        self.normaliser = normaliser or EvidenceNormaliser()
        self.attribute_extractor = attribute_extractor or AttributeExtractor()
        self.entity_mapper = entity_mapper or EntityExtractor()
        self.relationship_mapper = relationship_mapper or RelationshipMapper()

        # Kept for compatibility with the existing engine interface.
        # These rules are not automatically applied by this pipeline unless
        # a rule-evaluation stage is explicitly implemented.
        self.rules = tuple(
            rules if rules is not None else (SameTenantTemporalRule(),)
        )

        self.candidate_generator = candidate_generator or CandidateGenerator()
        self.scorer = scorer or CorrelationScorer()
        self.policy = policy or CrossTenantPolicy()
        self.causal_reasoner = causal_reasoner or CausalReasoner()
        self.graph_builder = graph_builder or EvidenceGraphBuilder()

    # ==================================================================
    # Main pipeline
    # ==================================================================

    def process(
        self,
        evidence_items: Iterable[Any],
        context: CorrelationContext | None = None,
    ) -> CorrelationResult:
        started_at = datetime.now(timezone.utc)
        timer_start = perf_counter()

        if context is None:
            context = CorrelationContext(
                analysis_id=self._analysis_id(started_at)
            )

        # 1. Normalise authoritative evidence.
        raw_items = tuple(evidence_items)
        canonical_items = tuple(self.normalise(item) for item in raw_items)

        evidence_by_id: dict[str, CanonicalEvidence] = {}
        for item in canonical_items:
            if item.evidence_id in evidence_by_id:
                raise ValueError(
                    "Duplicate evidence_id after normalisation: "
                    f"{item.evidence_id!r}. Evidence IDs must be unique "
                    "within one analysis."
                )
            evidence_by_id[item.evidence_id] = item

        # 2. Extract attributes, entities, and entity relationships.
        entities_by_evidence: dict[str, tuple[EvidenceEntity, ...]] = {}
        relationships: list[EvidenceRelationship] = []

        for evidence in canonical_items:
            extracted_attributes = self.attribute_extractor.extract(evidence)
            enriched = self._apply_attributes(evidence, extracted_attributes)

            entities = tuple(self.entity_mapper.extract(enriched))
            entities_by_evidence[enriched.evidence_id] = entities

            relationships.extend(
                self.relationship_mapper.map(enriched, entities)
            )

            evidence_by_id[enriched.evidence_id] = enriched

        # 3. Candidate generation.
        # Copy injected components so analysis-specific configuration does
        # not mutate a dependency shared by other calls to this engine.
        generator = copy(self.candidate_generator)
        if hasattr(generator, "temporal_window_seconds"):
            generator.temporal_window_seconds = (
                context.temporal_window_seconds
            )

        candidates = tuple(
            generator.generate(
                evidence_by_id.values(),
                entities_by_evidence,
            )
        )

        naive_comparison_count = (
            len(canonical_items) * max(len(canonical_items) - 1, 0) // 2
        )

        # 4. Configure a per-analysis scorer copy.
        scorer = copy(self.scorer)
        if hasattr(scorer, "threshold"):
            scorer.threshold = context.minimum_score
        if hasattr(scorer, "temporal_window_seconds"):
            scorer.temporal_window_seconds = context.temporal_window_seconds

        findings: list[CorrelationFinding] = []
        evaluated_candidate_count = 0
        rejected_candidate_count = 0
        policy_denied_count = 0

        causal_candidate_count = 0
        causal_evaluated_count = 0

        # 5. Scope, policy, score, causal reasoning, and finding construction.
        for candidate in candidates:
            if not self._candidate_in_scope(
                candidate,
                context,
                evidence_by_id=evidence_by_id,
            ):
                policy_denied_count += 1
                continue

            decision = self.policy.evaluate(candidate, context)
            if not decision.allowed:
                policy_denied_count += 1
                continue

            evaluated_candidate_count += 1

            score = scorer.score(
                candidate,
                evidence_by_id,
                permitted_features=context.permitted_feature_types,
            )

            if not score.passed:
                rejected_candidate_count += 1
                continue

            causal_candidate_count += 1
            causal_result = self.causal_reasoner.reason(
                candidate=candidate,
                evidence_by_id=evidence_by_id,
                context=context,
            )
            causal_evaluated_count += int(causal_result.considered)

            finding = self._build_finding(
                candidate=candidate,
                score=score,
                context=context,
                relationships=relationships,
                policy_id=decision.policy_id,
                policy_reason=decision.reason,
                causal_relationships=causal_result.relationships,
                causal_explanation=causal_result.explanation,
                causal_metadata=causal_result.metadata,
            )
            findings.append(finding)

        # 6. Deduplicate before building the graph or calculating final counts.
        final_findings = self._deduplicate_findings(findings)

        # 7. Build graph only from final, policy-approved findings.
        evidence_graph = self.graph_builder.build(
            analysis_id=context.analysis_id,
            evidence_by_id=evidence_by_id,
            entities_by_evidence=entities_by_evidence,
            relationships=relationships,
            findings=final_findings,
        )

        causal_finding_count = sum(
            bool(finding.causal_relationships)
            for finding in final_findings
        )
        causal_relationship_count = sum(
            len(finding.causal_relationships)
            for finding in final_findings
        )

        completed_at = datetime.now(timezone.utc)
        duration_seconds = max(0.0, perf_counter() - timer_start)

        candidate_reduction_ratio = (
            0.0
            if naive_comparison_count == 0
            else 1.0 - len(candidates) / naive_comparison_count
        )
        candidate_reduction_ratio = max(
            0.0, min(1.0, candidate_reduction_ratio)
        )

        provenance_reference_count = sum(
            len(finding.provenance) for finding in final_findings
        )
        provenance_complete = (
            all(
                bool(finding.provenance)
                and all(
                    reference.integrity_verified
                    and bool(reference.sha256)
                    for reference in finding.provenance
                )
                for finding in final_findings
            )
            if final_findings
            else True
        )

        warnings: list[str] = []
        if not candidates:
            warnings.append("No correlation candidates were generated.")

        # 8. Return the complete analysis result.
        return CorrelationResult(
            analysis_id=context.analysis_id,
            started_at=started_at,
            completed_at=completed_at,
            context=context,
            findings=final_findings,
            evidence_graph=evidence_graph,

            evidence_count=len(canonical_items),
            candidate_count=len(candidates),
            evaluated_candidate_count=evaluated_candidate_count,
            finding_count=len(final_findings),
            rejected_candidate_count=rejected_candidate_count,
            policy_denied_count=policy_denied_count,

            causal_candidate_count=causal_candidate_count,
            causal_evaluated_count=causal_evaluated_count,
            causal_finding_count=causal_finding_count,
            causal_relationship_count=causal_relationship_count,

            duration_seconds=duration_seconds,
            naive_comparison_count=naive_comparison_count,
            candidate_reduction_ratio=candidate_reduction_ratio,

            provenance_reference_count=provenance_reference_count,
            provenance_complete=provenance_complete,

            privacy_mode=context.privacy_mode,
            features_available=tuple(context.permitted_feature_types),

            engine_version=self.engine_version,
            configuration_version=context.configuration_version,
            warnings=tuple(warnings),

            metadata={
                "relationship_count": len(relationships),
                "entity_count": sum(
                    len(items) for items in entities_by_evidence.values()
                ),
                "candidate_generator": generator.__class__.__name__,
                "scorer": scorer.__class__.__name__,
                "policy": self.policy.__class__.__name__,
                "causal_reasoner": self.causal_reasoner.__class__.__name__,
                "graph_builder": self.graph_builder.__class__.__name__,
                "graph_node_count": evidence_graph.node_count,
                "graph_edge_count": evidence_graph.edge_count,
                "graph_causal_edge_count": evidence_graph.metadata.get(
                    "causal_edge_count", 0
                ),
                "configured_rule_count": len(self.rules),
            },
        )

    # ==================================================================
    # Evidence normalisation and enrichment
    # ==================================================================

    def normalise(self, item: Any) -> CanonicalEvidence:
        """Convert an input record to canonical evidence."""
        return self.normaliser.normalise(item)

    @staticmethod
    def _analysis_id(started_at: datetime) -> str:
        return "analysis:" + started_at.strftime("%Y%m%dT%H%M%S%fZ")

    @staticmethod
    def _apply_attributes(
        evidence: CanonicalEvidence,
        attributes: Any,
    ) -> CanonicalEvidence:
        """Merge extracted attributes without mutating frozen evidence."""
        if not isinstance(attributes, dict) or not attributes:
            return evidence

        merged = dict(evidence.attributes)
        merged.update(attributes)
        return evidence.model_copy(update={"attributes": merged})

    # ==================================================================
    # Candidate scope enforcement
    # ==================================================================

    @staticmethod
    def _candidate_in_scope(
        candidate: CorrelationCandidate,
        context: CorrelationContext,
        evidence_by_id: dict[str, CanonicalEvidence] | None = None,
    ) -> bool:
        """Check evidence identity, tenant scope, and requested time range."""

        if evidence_by_id is not None:
            # A candidate may only refer to records present in this analysis.
            if any(
                evidence_id not in evidence_by_id
                for evidence_id in candidate.evidence_ids
            ):
                return False

            evidence_items = [
                evidence_by_id[evidence_id]
                for evidence_id in candidate.evidence_ids
            ]

            # Fail closed when tenant scope cannot be established. This
            # prevents an un-attributed record being used to bridge tenants.
            if any(item.tenant_id is None for item in evidence_items):
                return False

            actual_tenants = {
                item.tenant_id
                for item in evidence_items
                if item.tenant_id is not None
            }

            if actual_tenants != set(candidate.tenant_ids):
                return False

            timestamps = [
                item.event_timestamp
                for item in evidence_items
                if item.event_timestamp is not None
            ]
            earliest = min(timestamps) if timestamps else None
            latest = max(timestamps) if timestamps else None
        else:
            earliest = candidate.earliest_timestamp
            latest = candidate.latest_timestamp

        requested_tenants = set(context.requested_tenants)
        candidate_tenants = set(candidate.tenant_ids)

        if requested_tenants and not candidate_tenants.issubset(
            requested_tenants
        ):
            return False

        if (
            context.start_time is not None
            and latest is not None
            and latest < context.start_time
        ):
            return False

        if (
            context.end_time is not None
            and earliest is not None
            and earliest > context.end_time
        ):
            return False

        return True

    # ==================================================================
    # Finding construction
    # ==================================================================

    def _build_finding(
        self,
        candidate: CorrelationCandidate,
        score: Any,
        context: CorrelationContext,
        relationships: list[EvidenceRelationship],
        policy_id: str,
        policy_reason: str,
        causal_relationships: tuple[CausalLink, ...] = (),
        causal_explanation: str = "",
        causal_metadata: dict[str, Any] | None = None,
    ) -> CorrelationFinding:
        """Build a finding with score, policy decision, and provenance."""

        relationship_ids = tuple(
            sorted(
                relationship.relationship_id
                for relationship in relationships
                if set(relationship.evidence_ids).intersection(
                    candidate.evidence_ids
                )
            )
        )

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

        causal_relationship_ids = tuple(
            sorted(link.relationship_id for link in causal_relationships)
        )

        return CorrelationFinding(
            finding_id=f"finding:{context.analysis_id}:{candidate.candidate_id}",
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
            causal_relationship_ids=causal_relationship_ids,
            causal_relationships=causal_relationships,
            graph_edge_id=f"edge:correlated:{candidate.candidate_id}",
            policy_id=policy_id,
            policy_allowed=True,
            policy_reason=policy_reason,
            event_start=candidate.earliest_timestamp,
            event_end=candidate.latest_timestamp,
            privacy_mode=context.privacy_mode,
            engine_version=self.engine_version,
            configuration_version=context.configuration_version,
            metadata={
                "blocking_keys": candidate.blocking_keys,
                "time_delta_seconds": candidate.time_delta_seconds,
                "shared_resources": candidate.shared_resources,
                "causal_reasoning": causal_metadata or {},
            },
        )

    # ==================================================================
    # Finding deduplication
    # ==================================================================

    @staticmethod
    def _deduplicate_findings(
        findings: Iterable[CorrelationFinding],
    ) -> tuple[CorrelationFinding, ...]:
        """Keep the first finding for each ID and return stable ordering."""
        unique: dict[str, CorrelationFinding] = {}
        for finding in findings:
            unique.setdefault(finding.finding_id, finding)

        return tuple(unique[key] for key in sorted(unique))
