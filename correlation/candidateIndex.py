from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from correlation.models import CanonicalEvidence, EvidenceEntity


@dataclass(frozen=True, slots=True)
class CandidatePair:
    """
    A lightweight pair produced by CandidateIndex.

    CandidatePair deliberately contains only the information required
    to identify the two evidence records and explain why they entered
    the candidate set.

    The expensive construction of CorrelationCandidate is left to
    CandidateGenerator.
    """

    first_evidence_id: str
    second_evidence_id: str

    blocking_keys: tuple[str, ...]

    @property
    def evidence_ids(self) -> tuple[str, str]:
        return (
            self.first_evidence_id,
            self.second_evidence_id,
        )


@dataclass(frozen=True, slots=True)
class CandidateIndexStats:
    """
    Statistics describing candidate-index behaviour.

    These values are useful for experimental evaluation because they
    allow the researcher to demonstrate the reduction from the
    theoretical pairwise search space to the indexed candidate set.
    """

    evidence_count: int
    theoretical_pair_count: int
    candidate_pair_count: int
    temporal_pair_count: int
    entity_pair_count: int
    resource_pair_count: int
    actor_pair_count: int
    tenant_pair_count: int
    reduction_ratio: float
    candidate_generation_ratio: float


class CandidateIndex:
    """
    Multi-dimensional blocking index for evidence correlation.

    The index creates candidate pairs from independent blocking
    dimensions:

        temporal
        entity
        resource
        actor
        tenant

    The dimensions are deliberately independent. A pair only needs
    to match one blocking dimension to enter the candidate set.

    This is a high-recall candidate-generation mechanism. Final
    correlation decisions remain the responsibility of the scorer.

    Complexity:

        index construction:
            approximately O(n)

        temporal candidate lookup:
            O(log n + k)

        entity/resource/actor/tenant blocks:
            O(k)

        overall:
            O(n log n + P)

    where P is the number of actual blocked candidate pairs rather
    than n².
    """

    def __init__(
        self,
        *,
        temporal_window_seconds: float = 60.0,
        include_tenant_blocking: bool = True,
    ) -> None:
        if temporal_window_seconds < 0:
            raise ValueError(
                "temporal_window_seconds must be >= 0"
            )

        self.temporal_window_seconds = float(
            temporal_window_seconds
        )

        self.include_tenant_blocking = (
            include_tenant_blocking
        )

        self._evidence: dict[
            str,
            CanonicalEvidence,
        ] = {}

        self._entities_by_evidence: dict[
            str,
            tuple[EvidenceEntity, ...],
        ] = {}

        self._temporal_entries: list[
            tuple[datetime, str]
        ] = []

        self._entity_index: dict[
            str,
            set[str],
        ] = defaultdict(set)

        self._resource_index: dict[
            str,
            set[str],
        ] = defaultdict(set)

        self._actor_index: dict[
            str,
            set[str],
        ] = defaultdict(set)

        self._tenant_index: dict[
            str,
            set[str],
        ] = defaultdict(set)

        self._temporal_timestamps: list[
            datetime
        ] = []

        self._built = False

        self._stats: CandidateIndexStats | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        evidence: Iterable[CanonicalEvidence],
        entities_by_evidence: dict[
            str,
            tuple[EvidenceEntity, ...],
        ] | None = None,
    ) -> None:
        """
        Build all indexes from canonical evidence.

        Building is deterministic. Evidence records are ordered by
        evidence_id before insertion so that repeated executions over
        the same evidence produce the same index and candidate set.
        """

        self._reset()

        if entities_by_evidence is None:
            entities_by_evidence = {}

        items = sorted(
            tuple(evidence),
            key=lambda item: item.evidence_id,
        )

        for item in items:
            self._add_evidence(
                item,
                entities_by_evidence.get(
                    item.evidence_id,
                    (),
                ),
            )

        self._temporal_entries.sort(
            key=lambda value: (
                value[0],
                value[1],
            )
        )

        self._temporal_timestamps = [
            timestamp
            for timestamp, _ in self._temporal_entries
        ]

        self._built = True

        self._stats = None

    def generate_pairs(self) -> tuple[CandidatePair, ...]:
        """
        Generate unique candidate pairs from the indexes.

        Every pair is canonicalised using evidence IDs, preventing
        A-B and B-A from appearing as separate candidates.
        """

        self._require_built()

        pair_keys: dict[
            tuple[str, str],
            set[str],
        ] = defaultdict(set)

        self._generate_temporal_pairs(pair_keys)
        self._generate_block_pairs(
            self._entity_index,
            pair_keys,
        )
        self._generate_block_pairs(
            self._resource_index,
            pair_keys,
        )
        self._generate_block_pairs(
            self._actor_index,
            pair_keys,
        )

        if self.include_tenant_blocking:
            self._generate_block_pairs(
                self._tenant_index,
                pair_keys,
            )

        candidates = [
            CandidatePair(
                first_evidence_id=pair[0],
                second_evidence_id=pair[1],
                blocking_keys=tuple(
                    sorted(blocking_keys)
                ),
            )
            for pair, blocking_keys in pair_keys.items()
        ]

        candidates.sort(
            key=lambda candidate: (
                candidate.first_evidence_id,
                candidate.second_evidence_id,
            )
        )

        self._update_statistics(
            pair_keys
        )

        return tuple(candidates)

    @property
    def stats(self) -> CandidateIndexStats:
        """
        Return statistics for the most recent candidate generation.
        """

        self._require_built()

        if self._stats is None:
            self.generate_pairs()

        assert self._stats is not None

        return self._stats

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------

    def _reset(self) -> None:
        self._evidence.clear()
        self._entities_by_evidence.clear()
        self._temporal_entries.clear()
        self._temporal_timestamps.clear()
        self._entity_index.clear()
        self._resource_index.clear()
        self._actor_index.clear()
        self._tenant_index.clear()

        self._built = False
        self._stats = None

    def _add_evidence(
        self,
        evidence: CanonicalEvidence,
        entities: tuple[EvidenceEntity, ...],
    ) -> None:
        evidence_id = evidence.evidence_id

        self._evidence[evidence_id] = evidence
        self._entities_by_evidence[evidence_id] = (
            tuple(entities)
        )

        if evidence.event_timestamp is not None:
            self._temporal_entries.append(
                (
                    evidence.event_timestamp,
                    evidence_id,
                )
            )

        for entity in entities:
            if entity.entity_id:
                self._entity_index[
                    f"entity:{entity.entity_id}"
                ].add(evidence_id)

        for resource in self._resource_values(evidence):
            self._resource_index[
                f"resource:{resource}"
            ].add(evidence_id)

        actor = self._actor_value(evidence)

        if actor:
            self._actor_index[
                f"actor:{actor}"
            ].add(evidence_id)

        if (
            self.include_tenant_blocking
            and evidence.tenant_id
        ):
            self._tenant_index[
                f"tenant:{evidence.tenant_id}"
            ].add(evidence_id)

    # ------------------------------------------------------------------
    # Temporal blocking
    # ------------------------------------------------------------------

    def _generate_temporal_pairs(
        self,
        pair_keys: dict[
            tuple[str, str],
            set[str],
        ],
    ) -> None:
        if not self._temporal_entries:
            return

        window = timedelta(
            seconds=self.temporal_window_seconds
        )

        for index, (
            timestamp,
            evidence_id,
        ) in enumerate(self._temporal_entries):

            lower = timestamp - window
            upper = timestamp + window

            start = bisect_left(
                self._temporal_timestamps,
                lower,
            )

            end = bisect_right(
                self._temporal_timestamps,
                upper,
            )

            for other_index in range(start, end):
                if other_index == index:
                    continue

                other_timestamp, other_id = (
                    self._temporal_entries[
                        other_index
                    ]
                )

                if evidence_id == other_id:
                    continue

                pair = self._canonical_pair(
                    evidence_id,
                    other_id,
                )

                pair_keys[pair].add(
                    "temporal:near"
                )

    # ------------------------------------------------------------------
    # Generic block generation
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_block_pairs(
        index: dict[str, set[str]],
        pair_keys: dict[
            tuple[str, str],
            set[str],
        ],
    ) -> None:
        """
        Generate pairs within each blocking bucket.

        A blocking bucket is expected to be substantially smaller than
        the complete evidence population.

        Extremely large buckets are therefore intentionally visible
        through candidate-index statistics rather than silently hidden.
        """

        for blocking_key in sorted(index):
            evidence_ids = sorted(
                index[blocking_key]
            )

            for position, first_id in enumerate(
                evidence_ids
            ):
                for second_id in evidence_ids[
                    position + 1 :
                ]:
                    pair = CandidateIndex._canonical_pair(
                        first_id,
                        second_id,
                    )

                    pair_keys[pair].add(
                        blocking_key
                    )

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _resource_values(
        evidence: CanonicalEvidence,
    ) -> set[str]:
        values: set[str] = set()

        if evidence.resource:
            values.add(
                str(evidence.resource)
            )

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
                value = str(value).strip()

                if value:
                    values.add(value)

        return values

    @staticmethod
    def _actor_value(
        evidence: CanonicalEvidence,
    ) -> str | None:
        if evidence.actor is None:
            return None

        value = str(evidence.actor).strip()

        if not value:
            return None

        return value

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical_pair(
        first_id: str,
        second_id: str,
    ) -> tuple[str, str]:
        if first_id < second_id:
            return (
                first_id,
                second_id,
            )

        return (
            second_id,
            first_id,
        )

    def _require_built(self) -> None:
        if not self._built:
            raise RuntimeError(
                "CandidateIndex must be built before "
                "candidate pairs can be generated"
            )

    # ------------------------------------------------------------------
    # Evaluation statistics
    # ------------------------------------------------------------------

    def _update_statistics(
        self,
        pair_keys: dict[
            tuple[str, str],
            set[str],
        ],
    ) -> None:
        evidence_count = len(
            self._evidence
        )

        theoretical_pair_count = (
            evidence_count
            * (evidence_count - 1)
            // 2
        )

        candidate_pair_count = len(
            pair_keys
        )

        temporal_pair_count = sum(
            1
            for keys in pair_keys.values()
            if "temporal:near" in keys
        )

        entity_pair_count = sum(
            1
            for keys in pair_keys.values()
            if any(
                key.startswith("entity:")
                for key in keys
            )
        )

        resource_pair_count = sum(
            1
            for keys in pair_keys.values()
            if any(
                key.startswith("resource:")
                for key in keys
            )
        )

        actor_pair_count = sum(
            1
            for keys in pair_keys.values()
            if any(
                key.startswith("actor:")
                for key in keys
            )
        )

        tenant_pair_count = sum(
            1
            for keys in pair_keys.values()
            if any(
                key.startswith("tenant:")
                for key in keys
            )
        )

        if theoretical_pair_count:
            reduction_ratio = (
                1.0
                - (
                    candidate_pair_count
                    / theoretical_pair_count
                )
            )

            candidate_generation_ratio = (
                candidate_pair_count
                / theoretical_pair_count
            )
        else:
            reduction_ratio = 0.0
            candidate_generation_ratio = 0.0

        self._stats = CandidateIndexStats(
            evidence_count=evidence_count,
            theoretical_pair_count=(
                theoretical_pair_count
            ),
            candidate_pair_count=(
                candidate_pair_count
            ),
            temporal_pair_count=(
                temporal_pair_count
            ),
            entity_pair_count=(
                entity_pair_count
            ),
            resource_pair_count=(
                resource_pair_count
            ),
            actor_pair_count=(
                actor_pair_count
            ),
            tenant_pair_count=(
                tenant_pair_count
            ),
            reduction_ratio=reduction_ratio,
            candidate_generation_ratio=(
                candidate_generation_ratio
            ),
        )