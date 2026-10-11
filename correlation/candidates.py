# correlation/candidates.py

from __future__ import annotations

from typing import Iterable

from correlation.candidateIndex import CandidateIndex
from correlation.models import (
    CandidateType,
    CanonicalEvidence,
    CorrelationCandidate,
    EvidenceEntity,
    EvidenceReference,
    ProvenanceReference,
)


class CandidateGenerator:
    """
    Generate deterministic correlation candidates from canonical evidence.

    CandidateIndex identifies potentially related evidence pairs using
    multiple blocking dimensions. CandidateGenerator enriches those pairs
    with tenant metadata, shared resources, actions, and provenance.

    Candidate generation does not determine whether a pair is a final
    correlation finding. That decision belongs to scoring and subsequent
    correlation-engine stages.
    """

    def __init__(self, temporal_window_seconds: float = 60.0) -> None:
        if temporal_window_seconds < 0:
            raise ValueError("temporal_window_seconds must be >= 0")

        self.temporal_window_seconds = temporal_window_seconds

    def generate(
        self,
        evidence: Iterable[CanonicalEvidence],
        entities_by_evidence: (
            dict[str, tuple[EvidenceEntity, ...]] | None
        ) = None,
    ) -> tuple[CorrelationCandidate, ...]:
        """
        Generate candidates using indexed, multidimensional blocking.

        The output is sorted by candidate ID to make results deterministic.
        """
        items = tuple(evidence)

        if entities_by_evidence is None:
            entities_by_evidence = {}

        evidence_by_id = {
            item.evidence_id: item
            for item in items
        }

        index = CandidateIndex(
            temporal_window_seconds=self.temporal_window_seconds,
            include_tenant_blocking=False,
        )

        index.build(
            items,
            entities_by_evidence=entities_by_evidence,
        )

        candidates: list[CorrelationCandidate] = []

        for pair in index.generate_pairs():
            first = evidence_by_id[pair.first_evidence_id]
            second = evidence_by_id[pair.second_evidence_id]

            candidate = self._build_candidate(
                first,
                second,
                entities_by_evidence,
                blocking_keys=pair.blocking_keys,
            )

            if candidate is not None:
                candidates.append(candidate)

        candidates.sort(
            key=lambda candidate: candidate.candidate_id
        )

        return tuple(candidates)

    def _build_candidate(
        self,
        first: CanonicalEvidence,
        second: CanonicalEvidence,
        entities_by_evidence: dict[
            str, tuple[EvidenceEntity, ...]
        ],
        blocking_keys: tuple[str, ...],
    ) -> CorrelationCandidate | None:
        evidence_ids = tuple(
            sorted(
                (
                    first.evidence_id,
                    second.evidence_id,
                )
            )
        )

        # Preserve known tenant identifiers without introducing None.
        known_tenant_ids = {
            tenant_id
            for tenant_id in (
                first.tenant_id,
                second.tenant_id,
            )
            if tenant_id is not None
        }

        tenant_ids = tuple(sorted(known_tenant_ids))
        cross_tenant = len(tenant_ids) > 1

        timestamps = tuple(
            timestamp
            for timestamp in (
                first.event_timestamp,
                second.event_timestamp,
            )
            if timestamp is not None
        )

        earliest_timestamp = min(timestamps) if timestamps else None
        latest_timestamp = max(timestamps) if timestamps else None

        time_delta_seconds: float | None = None

        if (
            first.event_timestamp is not None
            and second.event_timestamp is not None
        ):
            time_delta_seconds = abs(
                (
                    first.event_timestamp
                    - second.event_timestamp
                ).total_seconds()
            )

        first_entities = entities_by_evidence.get(
            first.evidence_id,
            (),
        )
        second_entities = entities_by_evidence.get(
            second.evidence_id,
            (),
        )

        first_entity_ids = {
            entity.entity_id
            for entity in first_entities
        }
        second_entity_ids = {
            entity.entity_id
            for entity in second_entities
        }

        shared_entity_ids = tuple(
            sorted(first_entity_ids & second_entity_ids)
        )

        shared_resources = self._shared_resources(first, second)
        related_actions = self._related_actions(first, second)

        normalized_blocking_keys = tuple(
            sorted(set(blocking_keys))
        )

        if not normalized_blocking_keys:
            return None

        generation_reasons: set[str] = set()

        if time_delta_seconds is not None:
            generation_reasons.add("temporal_proximity")

        if any(
            key.startswith("entity:")
            for key in normalized_blocking_keys
        ):
            generation_reasons.add("shared_entity")

        if any(
            key.startswith("resource:")
            for key in normalized_blocking_keys
        ):
            generation_reasons.add("shared_resource")

        if any(
            key.startswith("actor:")
            for key in normalized_blocking_keys
        ):
            generation_reasons.add("shared_actor_value")

        # Use one resolver for both reference types. An empty or
        # whitespace-only source_table must never be passed through.
        evidence_references = (
            EvidenceReference(
                evidence_id=first.evidence_id,
                source_table=self._source_table(first),
                sha256=first.sha256,
            ),
            EvidenceReference(
                evidence_id=second.evidence_id,
                source_table=self._source_table(second),
                sha256=second.sha256,
            ),
        )

        provenance = (
            self._provenance_reference(first),
            self._provenance_reference(second),
        )

        return CorrelationCandidate(
            candidate_id=(
                f"candidate:{evidence_ids[0]}:{evidence_ids[1]}"
            ),
            candidate_type=CandidateType.PAIR,
            evidence_ids=evidence_ids,
            evidence_references=evidence_references,
            tenant_ids=tenant_ids,
            cross_tenant=cross_tenant,
            generation_reasons=tuple(
                sorted(generation_reasons)
            ),
            blocking_keys=normalized_blocking_keys,
            earliest_timestamp=earliest_timestamp,
            latest_timestamp=latest_timestamp,
            time_delta_seconds=time_delta_seconds,
            shared_entity_ids=shared_entity_ids,
            shared_resources=shared_resources,
            related_actions=related_actions,
            provenance=provenance,
            metadata={
                "candidate_generator": self.__class__.__name__,
                "temporal_window_seconds": (
                    self.temporal_window_seconds
                ),
            },
        )

    @staticmethod
    def _source_table(evidence: CanonicalEvidence) -> str:
        """
        Resolve a non-empty source identifier for evidence references.

        Prefer the explicit source table, then a configured repository.
        The logical fallback is used for synthetic or not-yet-persisted
        canonical evidence that has no physical table identifier.
        """
        provenance = evidence.provenance or {}

        for key in ("source_table", "repository"):
            value = provenance.get(key)

            if value is not None:
                normalized = str(value).strip()

                if normalized:
                    return normalized

        return "canonical_evidence"

    @staticmethod
    def _shared_resources(
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> tuple[str, ...]:
        first_resources = CandidateGenerator._resource_values(first)
        second_resources = CandidateGenerator._resource_values(second)

        return tuple(
            sorted(first_resources & second_resources)
        )

    @staticmethod
    def _resource_values(
        evidence: CanonicalEvidence,
    ) -> set[str]:
        values: set[str] = set()

        if evidence.resource:
            values.add(str(evidence.resource))

        for key in (
            "resource",
            "resource_id",
            "path",
            "file",
            "file_path",
            "object",
        ):
            value = evidence.attributes.get(key)

            if value is not None:
                normalized = str(value).strip()

                if normalized:
                    values.add(normalized)

        return values

    @staticmethod
    def _related_actions(
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> tuple[str, ...]:
        first_action = CandidateGenerator._action_value(first)
        second_action = CandidateGenerator._action_value(second)

        if not first_action and not second_action:
            return ()

        if first_action and second_action:
            if first_action == second_action:
                return (first_action,)

            return tuple(
                sorted(
                    {
                        first_action,
                        second_action,
                    }
                )
            )

        return (first_action or second_action,)

    @staticmethod
    def _action_value(
        evidence: CanonicalEvidence,
    ) -> str | None:
        for key in (
            "operation",
            "action",
            "command",
            "syscall",
            "event_action",
        ):
            value = evidence.attributes.get(key)

            if value is not None:
                normalized = str(value).strip()

                if normalized:
                    return normalized

        if evidence.event_type:
            normalized_event_type = str(evidence.event_type).strip()

            if normalized_event_type:
                return normalized_event_type

        return None

    @staticmethod
    def _same_actor(
        first: CanonicalEvidence,
        second: CanonicalEvidence,
    ) -> bool:
        if first.actor is None or second.actor is None:
            return False

        return (
            first.actor == second.actor
            and first.actor != ""
        )

    @staticmethod
    def _provenance_reference(
        evidence: CanonicalEvidence,
    ) -> ProvenanceReference:
        return ProvenanceReference(
            evidence_id=evidence.evidence_id,
            source_table=CandidateGenerator._source_table(evidence),
            sha256=evidence.sha256,
            tenant_id=evidence.tenant_id,
            project_id=evidence.project_id,
            instance_name=evidence.instance_name,
            evidence_layer=evidence.layer,
            evidence_type=evidence.evidence_type,
            source=evidence.source,
        )