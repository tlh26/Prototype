# tests/correlation/test_engine_scoring_causal.py
from datetime import datetime, timedelta, timezone

from correlation.engine import CorrelationEngine
from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    EvidenceLayer,
)


UTC = timezone.utc


def make_evidence(
    evidence_id: str,
    event_type: str,
    timestamp: datetime,
    *,
    tenant_id: str = "tenant-a",
    resource: str | None = None,
):
    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name=f"web-{tenant_id[-1]}",
        layer=EvidenceLayer.INSTANCE,
        evidence_type="audit",
        event_type=event_type,
        source="auditd",
        source_path="/var/log/audit/audit.log",
        event_timestamp=timestamp,
        collected_at=timestamp,
        actor="alice",
        resource=resource,
        attributes={},
        raw_data=b"test",
        sha256="a" * 64,
        agent_id=f"agent-{tenant_id}",
        provenance={
            "source": "auditd",
            "collection_method": "host-agent",
        },
    )


def test_engine_integrates_scoring_and_causal_reasoning():
    now = datetime.now(UTC)

    create = make_evidence(
        "e1",
        "RESOURCE_CREATE",
        now,
        resource="/srv/app/data.db",
    )

    read = make_evidence(
        "e2",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/srv/app/data.db",
    )

    context = CorrelationContext(
        analysis_id="phase-3-integration",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        temporal_window_seconds=60.0,
        minimum_score=0.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            create,
            read,
        ),
        context=context,
    )

    assert result.findings

    finding = result.findings[0]

    # Phase 2
    assert finding.score is not None
    assert finding.score.value >= 0.0

    feature_names = {
        feature.feature_name
        for feature in finding.score.features
    }

    assert feature_names == {
        "temporal",
        "entity",
        "resource",
        "action",
        "provenance",
    }

    # Phase 3
    assert finding.causal_relationships

    causal = finding.causal_relationships[0]

    assert causal.relation.value == "provides"
    assert causal.source_evidence_id == "e1"
    assert causal.target_evidence_id == "e2"


def test_causal_reasoning_does_not_change_score():
    now = datetime.now(UTC)

    create = make_evidence(
        "e1",
        "RESOURCE_CREATE",
        now,
        resource="/srv/app/data.db",
    )

    read = make_evidence(
        "e2",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/srv/app/data.db",
    )

    context = CorrelationContext(
        analysis_id="score-invariance",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        temporal_window_seconds=60.0,
        minimum_score=0.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            create,
            read,
        ),
        context=context,
    )

    finding = result.findings[0]

    score_before_causal = finding.score.value

    assert finding.causal_relationships

    # Causal reasoning enriches the finding;
    # it does not add another scoring feature.
    assert finding.score.value == score_before_causal

    assert len(finding.score.features) == 5


def test_causal_reasoning_does_not_create_finding_by_itself():
    now = datetime.now(UTC)

    login = make_evidence(
        "e1",
        "LOGIN_SUCCESS",
        now,
    )

    session = make_evidence(
        "e2",
        "SESSION_CREATED",
        now + timedelta(seconds=5),
    )

    context = CorrelationContext(
        analysis_id="causal-not-score",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        temporal_window_seconds=60.0,
        minimum_score=1.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            login,
            session,
        ),
        context=context,
    )

    # Causal reasoning cannot bypass the scoring threshold.
    assert result.findings == ()


def test_result_reports_causal_statistics():
    now = datetime.now(UTC)

    create = make_evidence(
        "e1",
        "RESOURCE_CREATE",
        now,
        resource="/srv/app/data.db",
    )

    read = make_evidence(
        "e2",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        resource="/srv/app/data.db",
    )

    context = CorrelationContext(
        analysis_id="causal-statistics",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        minimum_score=0.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            create,
            read,
        ),
        context=context,
    )

    expected_count = sum(
        len(finding.causal_relationships)
        for finding in result.findings
    )

    assert result.causal_relationship_count == expected_count

    expected_findings = sum(
        1
        for finding in result.findings
        if finding.causal_relationships
    )

    assert result.causal_finding_count == expected_findings