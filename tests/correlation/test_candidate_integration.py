from __future__ import annotations

from datetime import datetime, timedelta, timezone
from itertools import combinations

import hashlib

from correlation.candidateIndex import CandidateIndex
from correlation.candidates import CandidateGenerator
from correlation.models import CanonicalEvidence


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

BASE_TIME = datetime(
    2026,
    1,
    1,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def make_evidence(
    evidence_id: str,
    *,
    tenant_id: str = "tenant-a",
    project_id: str | None = None,
    instance_name: str = "web-a",
    timestamp: datetime | None = None,
    actor: str | None = None,
    resource: str | None = None,
    event_type: str = "process_exec",
    evidence_type: str = "audit",
    source: str = "test",
    attributes: dict | None = None,
) -> CanonicalEvidence:
    """
    Construct valid CanonicalEvidence for candidate-generation
    integration tests.

    The fixture deliberately uses real SHA-256 values rather than
    synthetic hashes so that provenance/integrity fields remain
    representative of production evidence.
    """

    if timestamp is None:
        timestamp = BASE_TIME

    raw_data = (
        f"{evidence_id}|"
        f"{tenant_id}|"
        f"{timestamp.isoformat()}|"
        f"{actor}|"
        f"{resource}"
    ).encode()

    sha256 = hashlib.sha256(raw_data).hexdigest()

    merged_attributes = dict(attributes or {})

    if resource is not None:
        merged_attributes.setdefault("resource", resource)

    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=project_id or tenant_id,
        instance_name=instance_name,
        layer="instance",
        evidence_type=evidence_type,
        event_type=event_type,
        source=source,
        source_path="/var/log/audit/audit.log",
        event_timestamp=timestamp,
        collected_at=timestamp,
        actor=actor,
        resource=resource,
        attributes=merged_attributes,
        raw_data=raw_data,
        sha256=sha256,
        agent_id=f"agent-{tenant_id}",
        provenance={
            "source_table": "test_evidence",
            "tenant_id": tenant_id,
            "project_id": project_id or tenant_id,
            "instance_name": instance_name,
        },
    )


def candidate_pairs(candidates):
    """
    Convert generated CorrelationCandidates into a canonical set of
    unordered evidence-id pairs.
    """

    return {
        tuple(sorted(candidate.evidence_ids))
        for candidate in candidates
    }


def index_pairs(pairs):
    """
    Convert CandidateIndex CandidatePair objects into a canonical set
    of unordered evidence-id pairs.
    """

    return {
        tuple(sorted(pair.evidence_ids))
        for pair in pairs
    }


# ---------------------------------------------------------------------------
# CandidateIndex → CandidateGenerator integration
# ---------------------------------------------------------------------------


def test_index_and_generator_produce_consistent_candidate_pairs():
    """
    The CandidateIndex and CandidateGenerator must agree on which
    evidence pairs are eligible for downstream correlation.

    This verifies the architectural separation:

        CandidateIndex
            ↓
        candidate pairs
            ↓
        CandidateGenerator
            ↓
        enriched CorrelationCandidate
    """

    evidence = [
        # Temporal relationship.
        make_evidence(
            "temporal-a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "temporal-b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="bob",
        ),

        # Resource relationship, deliberately outside the temporal window.
        make_evidence(
            "resource-a",
            timestamp=BASE_TIME + timedelta(minutes=5),
            resource="/tmp/shared-object",
        ),
        make_evidence(
            "resource-b",
            timestamp=BASE_TIME + timedelta(minutes=10),
            resource="/tmp/shared-object",
        ),

        # Actor relationship, deliberately outside the temporal window.
        make_evidence(
            "actor-a",
            timestamp=BASE_TIME + timedelta(minutes=15),
            actor="charlie",
        ),
        make_evidence(
            "actor-b",
            timestamp=BASE_TIME + timedelta(minutes=20),
            actor="charlie",
        ),

        # Completely unrelated evidence.
        make_evidence(
            "unrelated",
            timestamp=BASE_TIME + timedelta(hours=2),
            actor="nobody",
            resource="/tmp/unrelated",
        ),
    ]

    entities_by_evidence = {}

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(
        evidence,
        entities_by_evidence=entities_by_evidence,
    )

    indexed_pairs = index.generate_pairs()

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(
        evidence,
        entities_by_evidence=entities_by_evidence,
    )

    assert candidate_pairs(candidates) == index_pairs(indexed_pairs)


def test_temporal_blocking_survives_index_to_generator_pipeline():
    """
    Evidence within the configured temporal window must propagate from
    CandidateIndex into CandidateGenerator.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(seconds=59),
            actor="bob",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.evidence_ids == ("a", "b")
    assert "temporal:near" in candidate.blocking_keys
    assert "temporal_proximity" in candidate.generation_reasons


def test_non_temporal_resource_blocking_survives_pipeline():
    """
    Resource blocking must be capable of producing a candidate even
    when the evidence falls outside the temporal blocking window.

    This protects against accidentally reintroducing a global temporal
    rejection into CandidateGenerator.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            resource="/tmp/shared-object",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(minutes=5),
            resource="/tmp/shared-object",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.evidence_ids == ("a", "b")
    assert "resource:/tmp/shared-object" in candidate.blocking_keys
    assert "shared_resource" in candidate.generation_reasons
    assert "temporal:near" not in candidate.blocking_keys


def test_non_temporal_actor_blocking_survives_pipeline():
    """
    Actor blocking must independently generate candidates outside the
    temporal window.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(minutes=5),
            actor="alice",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.evidence_ids == ("a", "b")
    assert "actor:alice" in candidate.blocking_keys
    assert "shared_actor_value" in candidate.generation_reasons
    assert "temporal:near" not in candidate.blocking_keys


def test_multiple_blocking_dimensions_are_preserved():
    """
    A candidate matching multiple blocking dimensions should retain all
    applicable reasons rather than collapsing the relationship to one
    dimension.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/shared-object",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="alice",
            resource="/tmp/shared-object",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.evidence_ids == ("a", "b")

    assert "temporal:near" in candidate.blocking_keys
    assert "actor:alice" in candidate.blocking_keys
    assert "resource:/tmp/shared-object" in candidate.blocking_keys

    assert "temporal_proximity" in candidate.generation_reasons
    assert "shared_actor_value" in candidate.generation_reasons
    assert "shared_resource" in candidate.generation_reasons


# ---------------------------------------------------------------------------
# Cross-tenant integration
# ---------------------------------------------------------------------------


def test_cross_tenant_candidate_is_generated():
    """
    Candidate generation must be capable of discovering a relationship
    across tenant boundaries.

    Privacy/authorization decisions occur later in the pipeline.
    Candidate generation should not silently discard a potentially
    relevant cross-tenant relationship.
    """

    evidence = [
        make_evidence(
            "tenant-a-event",
            tenant_id="tenant-a",
            project_id="tenant-a",
            instance_name="web-a",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/shared-object",
        ),
        make_evidence(
            "tenant-b-event",
            tenant_id="tenant-b",
            project_id="tenant-b",
            instance_name="web-b",
            timestamp=BASE_TIME + timedelta(seconds=20),
            actor="alice",
            resource="/tmp/shared-object",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.cross_tenant is True

    assert set(candidate.tenant_ids) == {
        "tenant-a",
        "tenant-b",
    }

    assert "temporal:near" in candidate.blocking_keys
    assert "actor:alice" in candidate.blocking_keys
    assert "resource:/tmp/shared-object" in candidate.blocking_keys


def test_same_tenant_blocking_is_not_required_for_candidate_generation():
    """
    CandidateGenerator deliberately disables tenant blocking in the
    CandidateIndex.

    Tenant membership is a scope/policy attribute, not itself a
    correlation signal.
    """

    evidence = [
        make_evidence(
            "a",
            tenant_id="tenant-a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "b",
            tenant_id="tenant-a",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="bob",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.cross_tenant is False
    assert "tenant:tenant-a" not in candidate.blocking_keys
    assert "temporal:near" in candidate.blocking_keys


# ---------------------------------------------------------------------------
# Search-space reduction
# ---------------------------------------------------------------------------


def test_candidate_index_reduces_theoretical_search_space():
    """
    Candidate blocking should reduce the number of pairs passed to
    downstream correlation.

    This is an important empirical property of the new architecture.
    """

    evidence = []

    for index in range(20):
        evidence.append(
            make_evidence(
                f"event-{index:02d}",
                timestamp=BASE_TIME + timedelta(minutes=index * 10),
                actor=f"actor-{index}",
                resource=f"/tmp/resource-{index}",
            )
        )

    # Add one known temporal relationship.
    evidence.append(
        make_evidence(
            "related-temporal-a",
            timestamp=BASE_TIME + timedelta(hours=5),
            actor="special-a",
        )
    )

    evidence.append(
        make_evidence(
            "related-temporal-b",
            timestamp=BASE_TIME + timedelta(hours=5, seconds=30),
            actor="special-b",
        )
    )

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()
    stats = index.stats

    theoretical_pairs = len(evidence) * (len(evidence) - 1) // 2

    assert stats.evidence_count == len(evidence)
    assert stats.theoretical_pair_count == theoretical_pairs
    assert stats.candidate_pair_count == len(pairs)

    assert stats.candidate_pair_count < stats.theoretical_pair_count
    assert stats.reduction_ratio > 0
    assert 0 <= stats.candidate_generation_ratio < 1


def test_candidate_generator_preserves_known_relationship_recall():
    """
    Blocking must reduce the search space without eliminating the
    deliberately constructed relationships.
    """

    evidence = [
        # Known temporal relationship.
        make_evidence(
            "temporal-a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "temporal-b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="bob",
        ),

        # Known resource relationship outside temporal window.
        make_evidence(
            "resource-a",
            timestamp=BASE_TIME + timedelta(minutes=10),
            resource="/tmp/shared",
        ),
        make_evidence(
            "resource-b",
            timestamp=BASE_TIME + timedelta(minutes=20),
            resource="/tmp/shared",
        ),

        # Known actor relationship outside temporal window.
        make_evidence(
            "actor-a",
            timestamp=BASE_TIME + timedelta(minutes=30),
            actor="charlie",
        ),
        make_evidence(
            "actor-b",
            timestamp=BASE_TIME + timedelta(minutes=40),
            actor="charlie",
        ),

        # No relationship.
        make_evidence(
            "unrelated",
            timestamp=BASE_TIME + timedelta(hours=3),
            actor="nobody",
            resource="/tmp/unrelated",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    pairs = candidate_pairs(candidates)

    assert ("temporal-a", "temporal-b") in pairs
    assert ("resource-a", "resource-b") in pairs
    assert ("actor-a", "actor-b") in pairs

    assert ("temporal-a", "unrelated") not in pairs
    assert ("resource-a", "unrelated") not in pairs
    assert ("actor-a", "unrelated") not in pairs


# ---------------------------------------------------------------------------
# Candidate determinism and enrichment
# ---------------------------------------------------------------------------


def test_candidate_generation_is_deterministic():
    """
    Candidate generation should produce the same candidate identifiers
    and relationships regardless of input ordering.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="alice",
        ),
        make_evidence(
            "c",
            timestamp=BASE_TIME + timedelta(seconds=45),
            resource="/tmp/shared",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    forward = generator.generate(evidence)
    reverse = generator.generate(tuple(reversed(evidence)))

    forward_ids = [candidate.candidate_id for candidate in forward]
    reverse_ids = [candidate.candidate_id for candidate in reverse]

    assert forward_ids == reverse_ids

    assert candidate_pairs(forward) == candidate_pairs(reverse)


def test_candidate_contains_provenance_and_tenant_information():
    """
    Candidate enrichment must retain the metadata needed by downstream
    scoring, policy enforcement, explainability, and auditability.
    """

    evidence = [
        make_evidence(
            "a",
            tenant_id="tenant-a",
            project_id="project-a",
            instance_name="web-a",
            timestamp=BASE_TIME,
            actor="alice",
        ),
        make_evidence(
            "b",
            tenant_id="tenant-b",
            project_id="project-b",
            instance_name="web-b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="alice",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.cross_tenant is True

    assert set(candidate.tenant_ids) == {
        "tenant-a",
        "tenant-b",
    }

    assert len(candidate.evidence_references) == 2
    assert len(candidate.provenance) == 2

    assert candidate.metadata["candidate_generator"] == "CandidateGenerator"


# ---------------------------------------------------------------------------
# Regression: no hidden pairwise CandidateGenerator implementation
# ---------------------------------------------------------------------------


def test_candidate_generator_matches_index_candidate_set():
    """
    Regression test for the architectural refactor.

    CandidateGenerator must expose exactly the candidates produced by
    CandidateIndex with the same blocking configuration.

    This prevents a future change from accidentally restoring an
    independent O(n²) candidate-selection implementation inside
    CandidateGenerator.
    """

    evidence = [
        make_evidence(
            "a",
            timestamp=BASE_TIME,
            actor="alice",
            resource="/tmp/a",
        ),
        make_evidence(
            "b",
            timestamp=BASE_TIME + timedelta(seconds=30),
            actor="bob",
            resource="/tmp/b",
        ),
        make_evidence(
            "c",
            timestamp=BASE_TIME + timedelta(minutes=5),
            actor="alice",
            resource="/tmp/c",
        ),
        make_evidence(
            "d",
            timestamp=BASE_TIME + timedelta(minutes=10),
            actor="dave",
            resource="/tmp/shared",
        ),
        make_evidence(
            "e",
            timestamp=BASE_TIME + timedelta(minutes=15),
            actor="eve",
            resource="/tmp/shared",
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    expected_pairs = index_pairs(index.generate_pairs())

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    actual_pairs = candidate_pairs(candidates)

    assert actual_pairs == expected_pairs