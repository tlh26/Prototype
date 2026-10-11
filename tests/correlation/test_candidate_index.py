from __future__ import annotations

from datetime import datetime, timedelta, timezone

from correlation.candidateIndex import CandidateIndex
from correlation.models import CanonicalEvidence


def make_evidence(
    evidence_id: str,
    *,
    tenant_id: str = "tenant-a",
    timestamp: datetime | None = None,
    actor: str | None = None,
    resource: str | None = None,
    attributes: dict | None = None,
) -> CanonicalEvidence:

    if timestamp is None:
        timestamp = datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        )

    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name="web",
        event_timestamp=timestamp,
        actor=actor,
        resource=resource,
        attributes=attributes or {},
        event_type="file",
        evidence_type="audit",
        layer="instance",
        source="test",
        source_path=None,
        collected_at=timestamp,
        raw_data=b"test-evidence",
        sha256=(
            f"{evidence_id}"
            + "0" * max(
                0,
                64 - len(evidence_id),
            )
        ),
        agent_id="test-agent",
        provenance={
            "source_table": "test_evidence",
        },
        sequence_start=None,
        sequence_end=None,
    )


def test_temporal_index_generates_nearby_pairs():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            "a",
            timestamp=base,
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(
                seconds=10
            ),
        ),
        make_evidence(
            "c",
            timestamp=base + timedelta(
                seconds=120
            ),
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert (
        ("a", "b")
        in {
            pair.evidence_ids
            for pair in pairs
        }
    )

    assert (
        ("a", "c")
        not in {
            pair.evidence_ids
            for pair in pairs
        }
    )


def test_entity_blocking_generates_pair():
    evidence = [
        make_evidence("a"),
        make_evidence("b"),
    ]

    from correlation.models import EvidenceEntity

    entities = {
        "a": (
            EvidenceEntity(
                entity_id="user:alice",
                entity_type="user",
                value="alice",
            ),
        ),
        "b": (
            EvidenceEntity(
                entity_id="user:alice",
                entity_type="user",
                value="alice",
            ),
        ),
    }

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(
        evidence,
        entities,
    )

    pairs = index.generate_pairs()

    assert len(pairs) == 1

    assert (
        "entity:user:alice"
        in pairs[0].blocking_keys
    )


def test_resource_blocking_generates_pair():
    evidence = [
        make_evidence(
            "a",
            resource="/etc/passwd",
        ),
        make_evidence(
            "b",
            resource="/etc/passwd",
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert len(pairs) == 1

    assert (
        "resource:/etc/passwd"
        in pairs[0].blocking_keys
    )


def test_actor_blocking_generates_pair():
    evidence = [
        make_evidence(
            "a",
            actor="alice",
        ),
        make_evidence(
            "b",
            actor="alice",
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert len(pairs) == 1

    assert (
        "actor:alice"
        in pairs[0].blocking_keys
    )


def test_multiple_blocking_reasons_are_merged():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            "a",
            timestamp=base,
            actor="alice",
            resource="/tmp/x",
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(
                seconds=5
            ),
            actor="alice",
            resource="/tmp/x",
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert len(pairs) == 1

    assert set(
        pairs[0].blocking_keys
    ) == {
        "temporal:near",
        "actor:alice",
        "resource:/tmp/x",
    }


def test_pairs_are_deduplicated():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            "a",
            timestamp=base,
            actor="alice",
            resource="/tmp/x",
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(
                seconds=5
            ),
            actor="alice",
            resource="/tmp/x",
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert len(pairs) == 1


def test_outside_temporal_window_is_not_candidate():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            "a",
            timestamp=base,
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(
                seconds=120
            ),
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert pairs == ()


def test_cross_tenant_temporal_candidate_is_allowed():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            "a",
            tenant_id="tenant-a",
            timestamp=base,
        ),
        make_evidence(
            "b",
            tenant_id="tenant-b",
            timestamp=base + timedelta(
                seconds=5
            ),
        ),
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    assert len(pairs) == 1


def test_statistics_measure_candidate_reduction():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence(
            f"event-{index}",
            timestamp=base + timedelta(
                seconds=index * 300
            ),
        )
        for index in range(10)
    ]

    index = CandidateIndex(
        temporal_window_seconds=60,
        include_tenant_blocking=False,
    )

    index.build(evidence)

    pairs = index.generate_pairs()

    stats = index.stats

    assert stats.evidence_count == 10
    assert stats.theoretical_pair_count == 45
    assert stats.candidate_pair_count == len(
        pairs
    )
    assert (
        stats.candidate_pair_count
        < stats.theoretical_pair_count
    )
    assert stats.reduction_ratio > 0