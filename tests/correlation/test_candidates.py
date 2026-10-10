from datetime import datetime, timedelta, timezone

from correlation.candidates import CandidateGenerator
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

    raw_data = f"test-evidence:{evidence_id}".encode()

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
        raw_data=raw_data,
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


def test_generator_returns_candidate_for_temporally_close_events():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence("a", timestamp=base),
        make_evidence(
            "b",
            timestamp=base + timedelta(seconds=10),
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert set(candidate.evidence_ids) == {"a", "b"}
    assert candidate.cross_tenant is False
    assert candidate.tenant_ids == ("tenant-a",)


def test_generator_excludes_events_outside_temporal_window():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence("a", timestamp=base),
        make_evidence(
            "b",
            timestamp=base + timedelta(seconds=120),
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 0


def test_generator_preserves_temporal_generation_reason():
    base = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    evidence = [
        make_evidence("a", timestamp=base),
        make_evidence(
            "b",
            timestamp=base + timedelta(seconds=10),
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert "temporal_proximity" in candidate.generation_reasons
    assert "temporal:near" in candidate.blocking_keys


def test_generator_preserves_shared_resource():
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
            resource="/etc/passwd",
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(minutes=5),
            resource="/etc/passwd",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert "/etc/passwd" in candidate.shared_resources
    assert "shared_resource" in candidate.generation_reasons


def test_generator_preserves_shared_actor():
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
        ),
        make_evidence(
            "b",
            timestamp=base + timedelta(minutes=5),
            actor="alice",
        ),
    ]

    generator = CandidateGenerator(
        temporal_window_seconds=60,
    )

    candidates = generator.generate(evidence)

    assert len(candidates) == 1

    candidate = candidates[0]

    # assert "alice" in candidate.metadata.get("shared_actors", ())
    assert "shared_actor_value" in candidate.generation_reasons
    assert "actor:alice" in candidate.blocking_keys
def test_generator_marks_cross_tenant_candidate():
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
            actor="alice",
        ),
        make_evidence(
            "b",
            tenant_id="tenant-b",
            timestamp=base + timedelta(seconds=10),
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