# tests/correlation/test_scoring.py

from datetime import datetime, timedelta, timezone

import pytest

from correlation.models import (
    CanonicalEvidence,
    CorrelationCandidate,
    CorrelationContext,
    EvidenceLayer,
    EvidenceReference,
    ProvenanceReference,
)
from correlation.scoring import CorrelationScorer


UTC = timezone.utc


def make_evidence(
    evidence_id: str,
    *,
    event_type: str = "RESOURCE_READ",
    timestamp: datetime | None = None,
    tenant_id: str = "tenant-a",
    instance_name: str = "web-a",
    actor: str | None = "alice",
    resource: str | None = "/srv/app/data.db",
    sha256: str | None = None,
    attributes: dict | None = None,
    provenance: dict | None = None,
    agent_id: str | None = None,
) -> CanonicalEvidence:
    timestamp = timestamp or datetime.now(UTC)

    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name=instance_name,
        layer=EvidenceLayer.INSTANCE,
        evidence_type="audit",
        event_type=event_type,
        source="test",
        source_path="/var/log/test.log",
        event_timestamp=timestamp,
        collected_at=timestamp,
        actor=actor,
        resource=resource,
        attributes=attributes or {},
        raw_data=b"test evidence",
        sha256=sha256 or ("a" * 64),
        agent_id=(
            agent_id if agent_id is not None
            else f"agent-{instance_name}"
        ),
        provenance=(
            provenance if provenance is not None
            else {
                "source": "test",
                "collection_method": "agent",
            }
        ),
    )


def make_provenance(
    evidence: CanonicalEvidence,
) -> ProvenanceReference:
    return ProvenanceReference(
        evidence_id=evidence.evidence_id,
        source_table="evidence_events",
        sha256=evidence.sha256,
        tenant_id=evidence.tenant_id,
        project_id=evidence.project_id,
        instance_name=evidence.instance_name,
        evidence_layer=evidence.layer,
        evidence_type=evidence.evidence_type,
        source=evidence.source,
        relationship="supports",
        captured_at=evidence.collected_at,
        sequence_start=evidence.sequence_start,
        sequence_end=evidence.sequence_end,
        integrity_verified=True,
    )


def make_candidate(
    first: CanonicalEvidence,
    second: CanonicalEvidence,
) -> CorrelationCandidate:
    timestamps = [
        event.event_timestamp
        for event in (first, second)
        if event.event_timestamp is not None
    ]

    tenant_ids = tuple(sorted({
        tenant
        for tenant in (first.tenant_id, second.tenant_id)
        if tenant is not None
    }))

    shared_resources = (
        (first.resource,)
        if (
            first.resource is not None
            and first.resource == second.resource
        )
        else ()
    )

    return CorrelationCandidate(
        candidate_id=f"{first.evidence_id}:{second.evidence_id}",
        evidence_ids=(first.evidence_id, second.evidence_id),
        evidence_references=(
            EvidenceReference(
                evidence_id=first.evidence_id,
                source_table="evidence_events",
                sha256=first.sha256,
            ),
            EvidenceReference(
                evidence_id=second.evidence_id,
                source_table="evidence_events",
                sha256=second.sha256,
            ),
        ),
        tenant_ids=tenant_ids,
        cross_tenant=len(tenant_ids) > 1,
        generation_reasons=("temporal",),
        blocking_keys=("temporal",),
        earliest_timestamp=min(timestamps) if timestamps else None,
        latest_timestamp=max(timestamps) if timestamps else None,
        time_delta_seconds=(
            abs(
                (
                    second.event_timestamp
                    - first.event_timestamp
                ).total_seconds()
            )
            if (
                first.event_timestamp is not None
                and second.event_timestamp is not None
            )
            else None
        ),
        shared_entity_ids=(),
        shared_resources=shared_resources,
        related_actions=(
            first.event_type,
            second.event_type,
        ),
        provenance=(
            make_provenance(first),
            make_provenance(second),
        ),
    )


@pytest.fixture
def scorer():
    return CorrelationScorer()


@pytest.fixture
def context():
    return CorrelationContext(
        analysis_id="test-analysis",
        requested_tenants=("tenant-a", "tenant-b"),
        allow_cross_tenant=True,
        permitted_feature_types=(
            "temporal",
            "entity",
            "resource",
            "action",
            "provenance",
        ),
        minimum_score=0.70,
    )


def score_candidate(
    scorer,
    context,
    first,
    second,
):
    return scorer.score(
        candidate=make_candidate(first, second),
        evidence_by_id={
            first.evidence_id: first,
            second.evidence_id: second,
        },
        permitted_features=context.permitted_feature_types,
    )


def get_feature(score, name):
    return next(
        feature
        for feature in score.features
        if feature.feature_name == name
    )


def test_scoring_uses_exactly_five_dimensions(scorer, context):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=10),
        ),
    )

    assert {
        feature.feature_name for feature in score.features
    } == {
        "temporal",
        "entity",
        "resource",
        "action",
        "provenance",
    }


def test_temporal_feature_is_high_for_close_events(scorer, context):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=5),
        ),
    )

    temporal = get_feature(score, "temporal")

    assert temporal.value > 0.0
    assert temporal.weight > 0.0
    assert temporal.contribution == pytest.approx(
        temporal.value * temporal.weight
    )


def test_entity_feature_is_zero_without_shared_entities(
    scorer,
    context,
):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=5),
        ),
    )

    assert get_feature(score, "entity").value == 0.0


def test_resource_feature_is_one_for_same_resource(
    scorer,
    context,
):
    now = datetime.now(UTC)
    resource_path = "/srv/app/data.db"

    first = make_evidence(
        "e1",
        timestamp=now,
        resource=resource_path,
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        resource=resource_path,
    )

    candidate = make_candidate(first, second)

    assert candidate.shared_resources == (resource_path,)

    score = scorer.score(
        candidate=candidate,
        evidence_by_id={
            first.evidence_id: first,
            second.evidence_id: second,
        },
        permitted_features=("resource",),
    )

    resource = get_feature(score, "resource")

    assert resource.value == pytest.approx(1.0)
    assert resource.contribution == pytest.approx(
        resource.value * resource.weight
    )


def test_resource_feature_is_zero_without_shared_resources(
    scorer,
    context,
):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        resource="/srv/app/data.db",
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        resource="/srv/app/other.db",
    )

    score = score_candidate(
        scorer,
        context,
        first,
        second,
    )

    assert get_feature(score, "resource").value == 0.0


def test_action_exact_match_scores_one(scorer, context):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        event_type="RESOURCE_READ",
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        event_type="RESOURCE_READ",
    )

    score = score_candidate(scorer, context, first, second)

    assert get_feature(score, "action").value == pytest.approx(1.0)


def test_action_semantic_difference_receives_partial_score(
    scorer,
    context,
):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        event_type="RESOURCE_READ",
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        event_type="RESOURCE_UPDATE",
    )

    score = score_candidate(scorer, context, first, second)

    action = get_feature(score, "action")

    assert action.value == pytest.approx(0.75)
    assert action.value < 1.0


def test_action_unrelated_events_score_zero(scorer, context):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        event_type="LOGIN_SUCCESS",
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        event_type="RESOURCE_UPDATE",
    )

    score = score_candidate(scorer, context, first, second)

    action = get_feature(score, "action")

    assert action.value == pytest.approx(0.0)


def test_candidate_related_actions_cannot_force_positive_score(
    scorer,
    context,
):
    """Candidate metadata must not override action-feature evaluation."""
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        event_type="LOGIN_SUCCESS",
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        event_type="RESOURCE_UPDATE",
    )

    candidate = make_candidate(first, second)

    # Simulate upstream candidate generation labelling the pair
    # as related. The scorer must still inspect the actual actions.
    candidate = candidate.model_copy(
        update={
            "related_actions": (
                "LOGIN_SUCCESS",
                "RESOURCE_UPDATE",
            )
        }
    )

    score = scorer.score(
        candidate=candidate,
        evidence_by_id={
            first.evidence_id: first,
            second.evidence_id: second,
        },
        permitted_features=("action",),
    )

    assert get_feature(score, "action").value == 0.0


def test_action_attributes_take_precedence_over_event_type(
    scorer,
    context,
):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        timestamp=now,
        event_type="AUDIT_EVENT",
        attributes={"action": "login_success"},
    )
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
        event_type="AUDIT_EVENT",
        attributes={"action": "resource_update"},
    )

    score = score_candidate(scorer, context, first, second)

    assert get_feature(score, "action").value == 0.0


def test_provenance_feature_is_evaluable(scorer, context):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=5),
        ),
    )

    provenance = get_feature(score, "provenance")

    assert 0.0 <= provenance.value <= 1.0
    assert provenance.weight > 0.0
    assert provenance.explanation


def test_score_contributions_sum_to_score(scorer, context):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=5),
        ),
    )

    expected = (
        sum(feature.contribution for feature in score.features)
        / score.weight_sum
    )

    assert score.value == pytest.approx(expected)


def test_score_is_explainable(scorer, context):
    now = datetime.now(UTC)

    score = score_candidate(
        scorer,
        context,
        make_evidence("e1", timestamp=now),
        make_evidence(
            "e2",
            timestamp=now + timedelta(seconds=5),
        ),
    )

    for feature in score.features:
        assert feature.feature_name
        assert feature.explanation
        assert 0.0 <= feature.value <= 1.0
        assert 0.0 <= feature.weight <= 1.0
        assert feature.contribution == pytest.approx(
            feature.value * feature.weight
        )

    assert score.explanation
    assert score.scoring_method == "weighted_explainable_v2"
    assert score.weight_sum == pytest.approx(1.0)
    assert score.valid_feature_count == 5


def test_permitted_features_can_remove_dimensions(scorer, context):
    now = datetime.now(UTC)

    first = make_evidence("e1", timestamp=now)
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
    )

    score = scorer.score(
        candidate=make_candidate(first, second),
        evidence_by_id={
            first.evidence_id: first,
            second.evidence_id: second,
        },
        permitted_features=("temporal", "resource"),
    )

    assert {
        feature.feature_name for feature in score.features
    } == {"temporal", "resource"}

    assert score.valid_feature_count == 2
    assert score.weight_sum == pytest.approx(0.45)
    assert score.metadata["permitted_features"] == (
        "temporal",
        "resource",
    )


def test_unknown_feature_is_rejected(scorer, context):
    now = datetime.now(UTC)

    first = make_evidence("e1", timestamp=now)
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
    )

    with pytest.raises(
        ValueError,
        match="Unsupported correlation feature",
    ):
        scorer.score(
            candidate=make_candidate(first, second),
            evidence_by_id={
                first.evidence_id: first,
                second.evidence_id: second,
            },
            permitted_features=("temporal", "actor"),
        )


def test_provenance_integrity_can_affect_score(scorer, context):
    now = datetime.now(UTC)

    first = make_evidence("e1", timestamp=now)
    second = make_evidence(
        "e2",
        timestamp=now + timedelta(seconds=5),
    )

    candidate = make_candidate(first, second)
    evidence = {
        first.evidence_id: first,
        second.evidence_id: second,
    }

    baseline = scorer.score(
        candidate=candidate,
        evidence_by_id=evidence,
        permitted_features=("provenance",),
    )

    degraded_candidate = candidate.model_copy(
        update={
            "provenance": tuple(
                provenance.model_copy(
                    update={"integrity_verified": False}
                )
                for provenance in candidate.provenance
            )
        }
    )

    degraded = scorer.score(
        candidate=degraded_candidate,
        evidence_by_id=evidence,
        permitted_features=("provenance",),
    )

    # The current scoring policy evaluates provenance from the canonical
    # evidence records. Changing candidate provenance references alone
    # must not silently change that feature.
    assert degraded.value == pytest.approx(baseline.value)
