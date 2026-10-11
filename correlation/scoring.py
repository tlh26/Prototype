# correlation/scoring.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from correlation.models import (
    CanonicalEvidence,
    CorrelationCandidate,
    CorrelationFeature,
    CorrelationScore,
    EvidenceEntity,
    EntityType,
)


@dataclass(frozen=True)
class CorrelationWeights:
    """Explicit, reproducible weights for five scoring dimensions."""

    temporal: float = 0.25
    entity: float = 0.25
    resource: float = 0.20
    action: float = 0.15
    provenance: float = 0.15

    def __post_init__(self) -> None:
        values = self.as_dict()

        for name, value in values.items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} weight must be between 0 and 1"
                )

        if abs(sum(values.values()) - 1.0) > 1e-9:
            raise ValueError(
                "Correlation weights must sum to 1.0"
            )

    def as_dict(self) -> dict[str, float]:
        return {
            "temporal": self.temporal,
            "entity": self.entity,
            "resource": self.resource,
            "action": self.action,
            "provenance": self.provenance,
        }


class CorrelationScorer:
    """
    Explainable weighted scoring of generated evidence candidates.

    A score represents weighted evidential support, not a probability.
    Candidate-generation metadata is not allowed to override independently
    evaluated action similarity.
    """

    FEATURE_NAMES = (
        "temporal",
        "entity",
        "resource",
        "action",
        "provenance",
    )

    DEFAULT_FEATURES = FEATURE_NAMES

    CONTEXT_ENTITY_TYPES = frozenset({
        EntityType.TENANT,
        EntityType.PROJECT,
        EntityType.INSTANCE,
    })

    STRONG_ENTITY_TYPES = frozenset({
        EntityType.USER,
        EntityType.PROCESS,
    })

    # Related action pairs are explicit, deterministic rules.
    # They are not evidence of causation by themselves.
    COMPLEMENTARY_ACTION_PAIRS = frozenset({
        frozenset(("read", "write")),
        frozenset(("read", "modify")),
        frozenset(("read", "update")),
        frozenset(("open", "close")),
        frozenset(("connect", "accept")),
        frozenset(("create", "execute")),
        frozenset(("download", "execute")),
        frozenset(("write", "execute")),
        frozenset(("resource_read", "resource_update")),
        frozenset(("resource_read", "resource_write")),
        frozenset(("resource_read", "resource_modify")),
        frozenset(("resource_write", "resource_update")),
    })

    def __init__(
        self,
        weights: CorrelationWeights | None = None,
        threshold: float = 0.70,
        temporal_window_seconds: float = 60.0,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(
                "threshold must be between 0 and 1"
            )

        if temporal_window_seconds < 0:
            raise ValueError(
                "temporal_window_seconds must be >= 0"
            )

        self.weights = weights or CorrelationWeights()
        self.threshold = float(threshold)
        self.temporal_window_seconds = float(
            temporal_window_seconds
        )

    def score(
        self,
        candidate: CorrelationCandidate,
        evidence_by_id: dict[str, CanonicalEvidence],
        permitted_features: Iterable[str] | None = None,
    ) -> CorrelationScore:
        """Score a candidate using only permitted feature dimensions."""

        if len(candidate.evidence_ids) < 2:
            raise ValueError(
                "A correlation candidate must contain at least two evidence IDs"
            )

        try:
            first = evidence_by_id[candidate.evidence_ids[0]]
            second = evidence_by_id[candidate.evidence_ids[1]]
        except KeyError as exc:
            raise ValueError(
                f"Missing evidence for candidate: {exc.args[0]}"
            ) from exc

        permitted = (
            set(permitted_features)
            if permitted_features is not None
            else set(self.FEATURE_NAMES)
        )

        unknown = permitted - set(self.FEATURE_NAMES)
        if unknown:
            raise ValueError(
                "Unsupported correlation feature(s): "
                + ", ".join(sorted(unknown))
            )

        all_features = (
            self._temporal_feature(candidate),
            self._entity_feature(candidate),
            self._resource_feature(candidate),
            self._action_feature(first, second, candidate),
            self._provenance_feature(first, second),
        )

        features = tuple(
            feature
            for feature in all_features
            if feature.feature_name in permitted
            and feature.weight > 0.0
        )

        weight_sum = sum(feature.weight for feature in features)

        # Renormalise over permitted dimensions. Removing a feature does
        # not silently lower every remaining feature's relative influence.
        value = (
            sum(feature.contribution for feature in features) / weight_sum
            if weight_sum > 0.0
            else 0.0
        )
        value = max(0.0, min(1.0, value))

        return CorrelationScore(
            value=value,
            threshold=self.threshold,
            passed=value >= self.threshold,
            features=features,
            scoring_method="weighted_explainable_v2",
            weight_sum=weight_sum,
            valid_feature_count=len(features),
            explanation=self._build_explanation(
                value=value,
                threshold=self.threshold,
                features=features,
            ),
            metadata={
                "feature_dimensions": self.FEATURE_NAMES,
                "weights": self.weights.as_dict(),
                "temporal_window_seconds": (
                    self.temporal_window_seconds
                ),
                "permitted_features": tuple(
                    name
                    for name in self.FEATURE_NAMES
                    if name in permitted
                ),
                "score_interpretation": (
                    "weighted evidential support, not probability"
                ),
            },
        )

    # ------------------------------------------------------------------
    # Temporal
    # ------------------------------------------------------------------

    def _temporal_feature(
        self,
        candidate: CorrelationCandidate,
    ) -> CorrelationFeature:
        delta = candidate.time_delta_seconds
        window = self.temporal_window_seconds

        if delta is None:
            value = 0.0
            explanation = (
                "Comparable event timestamps are unavailable."
            )
        elif window <= 0:
            value = 1.0 if delta == 0.0 else 0.0
            explanation = (
                f"Temporal delta is {delta:.3f}s; "
                "the configured window is zero."
            )
        elif delta >= window:
            value = 0.0
            explanation = (
                f"Events are {delta:.3f}s apart, outside the "
                f"{window:.3f}s temporal window."
            )
        else:
            value = max(0.0, 1.0 - delta / window)
            explanation = (
                f"Events are {delta:.3f}s apart within the "
                f"{window:.3f}s temporal window."
            )

        return self._feature(
            name="temporal",
            value=value,
            weight=self.weights.temporal,
            explanation=explanation,
            evidence_ids=candidate.evidence_ids,
            attributes_used=(
                "event_timestamp",
                "temporal_window_seconds",
                "time_delta_seconds",
            ),
            metadata={
                "delta_seconds": delta,
                "window_seconds": window,
            },
        )

    # ------------------------------------------------------------------
    # Entity
    # ------------------------------------------------------------------

    def _entity_feature(
        self,
        candidate: CorrelationCandidate,
    ) -> CorrelationFeature:
        entity_ids = candidate.shared_entity_ids

        if not entity_ids:
            value = 0.0
            explanation = "No shared analytical entity was identified."
            entity_types: tuple[EvidenceEntity, ...] = ()
        else:
            entity_types = self._entity_types_from_candidate(candidate)

            strong = [
                entity for entity in entity_types
                if entity.entity_type in self.STRONG_ENTITY_TYPES
            ]
            context = [
                entity for entity in entity_types
                if entity.entity_type in self.CONTEXT_ENTITY_TYPES
            ]
            resources = [
                entity for entity in entity_types
                if entity.entity_type == EntityType.RESOURCE
            ]

            if strong:
                value = 1.0
                explanation = (
                    "Shared user/process entities provide strong "
                    "behavioural linkage."
                )
            elif context:
                value = 0.20
                explanation = (
                    "Only tenant/project/instance context is shared; "
                    "context alone provides weak behavioural support."
                )
            elif resources:
                value = 0.0
                explanation = (
                    "Shared resource entities are evaluated separately "
                    "to avoid double-counting resource similarity."
                )
            else:
                value = 0.25
                explanation = (
                    "A shared entity exists, but its type provides "
                    "limited behavioural evidence."
                )

        return self._feature(
            name="entity",
            value=value,
            weight=self.weights.entity,
            explanation=explanation,
            evidence_ids=candidate.evidence_ids,
            attributes_used=(
                "shared_entity_ids",
                "entity_type",
                "tenant_id",
                "instance_name",
            ),
            metadata={
                "shared_entity_count": len(entity_ids),
                "entity_types": tuple(sorted({
                    entity.entity_type.value
                    for entity in entity_types
                })),
            },
        )

    def _entity_types_from_candidate(
        self,
        candidate: CorrelationCandidate,
    ) -> tuple[EvidenceEntity, ...]:
        metadata_entities = candidate.metadata.get("shared_entities")

        if metadata_entities:
            resolved = tuple(
                entity
                for entity in metadata_entities
                if isinstance(entity, EvidenceEntity)
            )
            if resolved:
                return resolved

        inferred = []

        for key in candidate.blocking_keys:
            if not key.startswith("entity:"):
                continue

            parts = key.split(":", 2)
            if len(parts) != 3:
                continue

            try:
                entity_type = EntityType(parts[1])
            except ValueError:
                continue

            inferred.append(
                EvidenceEntity(
                    entity_id=key.removeprefix("entity:"),
                    entity_type=entity_type,
                    value="",
                )
            )

        return tuple(inferred)

    # ------------------------------------------------------------------
    # Resource
    # ------------------------------------------------------------------

    def _resource_feature(
        self,
        candidate: CorrelationCandidate,
    ) -> CorrelationFeature:
        resources = tuple(candidate.shared_resources)

        if not resources:
            value = 0.0
            explanation = "No shared resource was identified."
        else:
            # The candidate stores resources already established as shared.
            # Exact identity is a full match; additional shared resources
            # do not make the score exceed 1.0.
            value = 1.0
            explanation = (
                f"{len(resources)} shared resource(s) were identified. "
                "Exact resource overlap provides full resource-match support."
            )

        return self._feature(
            name="resource",
            value=value,
            weight=self.weights.resource,
            explanation=explanation,
            evidence_ids=candidate.evidence_ids,
            attributes_used=("resource", "shared_resources"),
            metadata={
                "shared_resource_count": len(resources),
                "shared_resources": resources,
            },
        )

    # ------------------------------------------------------------------
    # Action
    # ------------------------------------------------------------------

    def _action_feature(
        self,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
        candidate: CorrelationCandidate,
    ) -> CorrelationFeature:
        first_action = self._action(first)
        second_action = self._action(second)

        if first_action is None or second_action is None:
            # Missing action data is uncertainty, not evidence of
            # semantic similarity.
            value = 0.0
            explanation = (
                "Action comparison is unavailable because one or both "
                "events lack a normalized action."
            )
        elif first_action == second_action:
            value = 1.0
            explanation = (
                f"Both events have the same normalized action "
                f"'{first_action}'."
            )
        elif self._actions_are_complementary(
            first_action,
            second_action,
        ):
            value = 0.75
            explanation = (
                f"Actions '{first_action}' and '{second_action}' "
                "belong to a configured related-action pair."
            )
        else:
            value = 0.0
            explanation = (
                f"Actions '{first_action}' and '{second_action}' "
                "have no configured semantic relationship."
            )

        # IMPORTANT:
        # candidate.related_actions and candidate blocking keys are
        # generated upstream. Their presence must never force a positive
        # action score. The action feature is evaluated independently.

        return self._feature(
            name="action",
            value=value,
            weight=self.weights.action,
            explanation=explanation,
            evidence_ids=(first.evidence_id, second.evidence_id),
            attributes_used=(
                "operation",
                "action",
                "command",
                "syscall",
                "event_action",
                "event_type",
            ),
            metadata={
                "first_action": first_action,
                "second_action": second_action,
                "candidate_related_actions": candidate.related_actions,
            },
        )

    @staticmethod
    def _action(
        evidence: CanonicalEvidence,
    ) -> str | None:
        """Return the first available normalized action."""

        for key in (
            "operation",
            "action",
            "command",
            "syscall",
            "event_action",
        ):
            value = evidence.attributes.get(key)

            if value is not None and str(value).strip():
                return str(value).strip().lower()

        if evidence.event_type and str(evidence.event_type).strip():
            return str(evidence.event_type).strip().lower()

        return None

    @classmethod
    def _actions_are_complementary(
        cls,
        first: str,
        second: str,
    ) -> bool:
        """Check an explicit, symmetric action-pair allowlist."""

        return frozenset((first, second)) in cls.COMPLEMENTARY_ACTION_PAIRS

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    def _provenance_feature(
        self,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> CorrelationFeature:
        first_hash_valid = self._valid_sha256(first.sha256)
        second_hash_valid = self._valid_sha256(second.sha256)

        first_provenance = bool(first.provenance)
        second_provenance = bool(second.provenance)
        first_agent = bool(first.agent_id)
        second_agent = bool(second.agent_id)

        first_complete = (
            first_hash_valid and first_provenance and first_agent
        )
        second_complete = (
            second_hash_valid and second_provenance and second_agent
        )

        complete_count = sum((first_complete, second_complete))

        if complete_count == 2:
            value = 1.0
            explanation = (
                "Both records have valid hashes, provenance metadata, "
                "and acquisition-agent identity."
            )
        elif complete_count == 1:
            value = 0.50
            explanation = (
                "Only one record has complete integrity and acquisition "
                "provenance."
            )
        elif first_hash_valid and second_hash_valid:
            value = 0.25
            explanation = (
                "Both records have valid hashes, but provenance is "
                "incomplete. Hash presence alone does not establish a "
                "relationship."
            )
        else:
            value = 0.0
            explanation = (
                "Insufficient integrity/provenance information is "
                "available to support evidential reliability."
            )

        return self._feature(
            name="provenance",
            value=value,
            weight=self.weights.provenance,
            explanation=explanation,
            evidence_ids=(first.evidence_id, second.evidence_id),
            attributes_used=("sha256", "provenance", "agent_id"),
            metadata={
                "first_hash_valid": first_hash_valid,
                "second_hash_valid": second_hash_valid,
                "first_provenance_present": first_provenance,
                "second_provenance_present": second_provenance,
                "first_agent_present": first_agent,
                "second_agent_present": second_agent,
                "interpretation": "evidential_reliability",
            },
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _feature(
        *,
        name: str,
        value: float,
        weight: float,
        explanation: str,
        evidence_ids: tuple[str, ...],
        attributes_used: tuple[str, ...],
        metadata: dict[str, object] | None = None,
    ) -> CorrelationFeature:
        value = max(0.0, min(1.0, float(value)))
        weight = max(0.0, min(1.0, float(weight)))

        return CorrelationFeature(
            feature_name=name,
            value=value,
            weight=weight,
            contribution=value * weight,
            explanation=explanation,
            evidence_ids=evidence_ids,
            attributes_used=attributes_used,
            metadata=metadata or {},
        )

    @staticmethod
    def _valid_sha256(value: str | None) -> bool:
        if not value:
            return False

        normalized = value.strip().lower()

        return (
            len(normalized) == 64
            and all(
                character in "0123456789abcdef"
                for character in normalized
            )
        )

    @staticmethod
    def _build_explanation(
        *,
        value: float,
        threshold: float,
        features: tuple[CorrelationFeature, ...],
    ) -> str:
        ordered = tuple(sorted(
            features,
            key=lambda feature: (
                -feature.contribution,
                feature.feature_name,
            ),
        ))

        parts = [
            (
                f"Weighted correlation score {value:.4f}; "
                f"threshold {threshold:.4f}; "
                f"{'passed' if value >= threshold else 'not passed'}."
            )
        ]

        if ordered:
            strongest = ordered[0]
            parts.append(
                f"Strongest contributor: {strongest.feature_name} "
                f"({strongest.contribution:.4f})."
            )

        for feature in ordered:
            parts.append(
                f"{feature.feature_name}: value={feature.value:.4f}, "
                f"weight={feature.weight:.4f}, "
                f"contribution={feature.contribution:.4f}; "
                f"{feature.explanation}"
            )

        return " ".join(parts)