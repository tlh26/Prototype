from datetime import datetime, timedelta, timezone

import pytest

from correlation.causal import (
    ACTION_DEFINITIONS,
    CausalReasoner,
)
from correlation.models import (
    CanonicalEvidence,
    CausalRelation,
    CorrelationCandidate,
    CorrelationContext,
    EvidenceLayer,
    EvidenceReference,
    ProvenanceReference,
)


UTC = timezone.utc


def make_evidence(
    evidence_id: str,
    event_type: str,
    timestamp: datetime,
    *,
    tenant_id: str = "tenant-a",
    resource: str | None = None,
) -> CanonicalEvidence:
    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name=f"web-{tenant_id[-1]}",
        layer=EvidenceLayer.INSTANCE,
        evidence_type="audit",
        event_type=event_type,
        source="test",
        source_path="/var/log/test.log",
        event_timestamp=timestamp,
        collected_at=timestamp,
        actor="alice",
        resource=resource,
        attributes={},
        raw_data=b"test",
        sha256="a" * 64,
        agent_id=f"agent-{tenant_id}",
        provenance={
            "source": "test",
            "collection_method": "agent",
        },
    )


def make_provenance(evidence):
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
        integrity_verified=True,
    )


def make_candidate(first, second):
    tenant_ids = tuple(
        sorted(
            {
                first.tenant_id,
                second.tenant_id,
            }
        )
    )

    return CorrelationCandidate(
        candidate_id=f"{first.evidence_id}:{second.evidence_id}",
        evidence_ids=(
            first.evidence_id,
            second.evidence_id,
        ),
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
        earliest_timestamp=min(
            first.event_timestamp,
            second.event_timestamp,
        ),
        latest_timestamp=max(
            first.event_timestamp,
            second.event_timestamp,
        ),
        time_delta_seconds=abs(
            (
                second.event_timestamp
                - first.event_timestamp
            ).total_seconds()
        ),
        shared_resources=(
            (first.resource,)
            if (
                first.resource
                and first.resource == second.resource
            )
            else ()
        ),
        related_actions=(
            first.event_type,
            second.event_type,
        ),
        provenance=(
            make_provenance(first),
            make_provenance(second),
        ),
    )


def run_reasoner(reasoner, context, first, second):
    candidate = make_candidate(first, second)

    return reasoner.reason(
        candidate=candidate,
        evidence_by_id={
            first.evidence_id: first,
            second.evidence_id: second,
        },
        context=context,
    )


@pytest.fixture
def reasoner():
    return CausalReasoner()


@pytest.fixture
def context():
    return CorrelationContext(
        analysis_id="causal-test",
        requested_tenants=(
            "tenant-a",
            "tenant-b",
        ),
        allow_cross_tenant=True,
        temporal_window_seconds=60.0,
    )


def test_action_vocabulary_is_limited_to_prototype_actions(
    reasoner,
):
    expected = set(ACTION_DEFINITIONS)

    assert set(reasoner.action_definitions) == expected

    assert expected == {
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "LOGOUT",
        "SESSION_CREATED",
        "SESSION_TERMINATED",
        "RESOURCE_CREATE",
        "RESOURCE_READ",
        "RESOURCE_UPDATE",
        "FILE_CREATE",
        "FILE_READ",
    }


def test_login_success_enables_session_creation(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    login = make_evidence(
        "login",
        "LOGIN_SUCCESS",
        now,
    )

    session = make_evidence(
        "session",
        "SESSION_CREATED",
        now + timedelta(seconds=5),
    )

    result = run_reasoner(
        reasoner,
        context,
        login,
        session,
    )

    assert len(result.relationships) == 1

    link = result.relationships[0]

    assert link.relation == CausalRelation.ENABLES
    assert link.source_evidence_id == "login"
    assert link.target_evidence_id == "session"


def test_resource_create_provides_resource_read(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        resource="/srv/app/data.db",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/srv/app/data.db",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert len(result.relationships) == 1

    link = result.relationships[0]

    assert link.relation == CausalRelation.PROVIDES
    assert link.source_evidence_id == "create"
    assert link.target_evidence_id == "read"
    assert link.evidence_ids == (
        "create",
        "read",
    )


def test_file_create_provides_file_read(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "FILE_CREATE",
        now,
        resource="/tmp/evidence.txt",
    )

    read = make_evidence(
        "read",
        "FILE_READ",
        now + timedelta(seconds=3),
        resource="/tmp/evidence.txt",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert len(result.relationships) == 1
    assert (
        result.relationships[0].relation
        == CausalRelation.PROVIDES
    )


def test_session_termination_requires_session_creation(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    session_created = make_evidence(
        "create-session",
        "SESSION_CREATED",
        now,
    )

    session_terminated = make_evidence(
        "terminate-session",
        "SESSION_TERMINATED",
        now + timedelta(seconds=10),
    )

    result = run_reasoner(
        reasoner,
        context,
        session_created,
        session_terminated,
    )

    assert len(result.relationships) == 1

    link = result.relationships[0]

    assert link.relation == CausalRelation.REQUIRES
    assert link.source_evidence_id == "terminate-session"
    assert link.target_evidence_id == "create-session"


def test_causal_reasoning_rejects_events_outside_temporal_window(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        resource="/data/file",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=120),
        resource="/data/file",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert result.relationships == ()


def test_resource_causality_requires_shared_resource(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        resource="/data/file-a",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/data/file-b",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert result.relationships == ()


def test_unknown_action_produces_no_causal_relation(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    first = make_evidence(
        "e1",
        "UNKNOWN_EVENT",
        now,
    )

    second = make_evidence(
        "e2",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
    )

    result = run_reasoner(
        reasoner,
        context,
        first,
        second,
    )

    assert result.relationships == ()


def test_causal_relationship_is_explainable(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        resource="/data/file",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/data/file",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    link = result.relationships[0]

    assert link.relationship_id
    assert link.explanation
    assert 0.0 <= link.confidence <= 1.0
    assert link.evidence_ids == (
        "create",
        "read",
    )
    assert link.temporal_delta_seconds == 5.0


def test_causal_relationship_ids_are_deterministic(
    reasoner,
    context,
):
    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        resource="/data/file",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/data/file",
    )

    result_one = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    result_two = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert (
        result_one.relationships[0].relationship_id
        == result_two.relationships[0].relationship_id
    )


def test_cross_tenant_causal_reasoning_respects_policy(
    reasoner,
):
    context = CorrelationContext(
        analysis_id="causal-test",
        requested_tenants=(
            "tenant-a",
            "tenant-b",
        ),
        allow_cross_tenant=False,
    )

    now = datetime.now(UTC)

    create = make_evidence(
        "create",
        "RESOURCE_CREATE",
        now,
        tenant_id="tenant-a",
        resource="/data/file",
    )

    read = make_evidence(
        "read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        tenant_id="tenant-b",
        resource="/data/file",
    )

    result = run_reasoner(
        reasoner,
        context,
        create,
        read,
    )

    assert result.relationships == ()