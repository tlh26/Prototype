from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from correlation.engine import CorrelationEngine
from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    EvidenceLayer,
    PrivacyMode,
)
from correlation.privacy import PrivacyControls
from correlation.scoring import CorrelationScorer


BASE_TIME = datetime(2026, 10, 19, 10, 35, tzinfo=timezone.utc)
TEST_PRIVACY_KEY = "test-correlation-privacy-key-for-unit-tests"


def make_evidence(
    evidence_id: str,
    *,
    tenant_id: str = "tenant-a",
    timestamp: datetime = BASE_TIME,
) -> CanonicalEvidence:
    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=f"{tenant_id}-project",
        instance_name="web-01",
        layer=EvidenceLayer.INSTANCE,
        evidence_type="audit",
        event_type="FILE_READ",
        source="audit-agent",
        source_path="/var/log/audit.log",
        event_timestamp=timestamp,
        collected_at=timestamp + timedelta(seconds=2),
        actor="alice",
        uid=1200,
        resource="/srv/private/report.log",
        attributes={
            "operation": "read",
            "username": "alice",
            "path": "/srv/private/report.log",
        },
        raw_data=b"private raw evidence",
        sha256="a" * 64,
        agent_id="agent-01",
        provenance={
            "source_table": "evidence_events",
            "acquisition_layer": "instance",
            "agent_id": "agent-01",
        },
    )


def test_pseudonymisation_is_stable_and_preserves_authorised_tenant_pair():
    controls = PrivacyControls(TEST_PRIVACY_KEY)
    context = CorrelationContext(
        analysis_id="pseudo-analysis",
        privacy_mode=PrivacyMode.PSEUDONYMISED,
        allow_cross_tenant=True,
        allowed_tenant_pairs=(("tenant-a", "tenant-b"),),
    )
    result_context = controls.prepare_context(context)

    first = controls.project_evidence(make_evidence("evt-1"), result_context)
    second = controls.project_evidence(make_evidence("evt-2"), result_context)

    assert first.actor != "alice"
    assert first.actor == second.actor
    assert first.tenant_id != "tenant-a"
    assert first.resource != "/srv/private/report.log"
    assert first.attributes["username"] == first.actor
    assert first.raw_data == b""
    assert "tenant-a" not in str(result_context.allowed_tenant_pairs)
    assert first.provenance["source_table"] == "evidence_events"


def test_generalisation_coarsens_time_identity_and_resource_values():
    controls = PrivacyControls(TEST_PRIVACY_KEY)
    context = controls.prepare_context(
        CorrelationContext(
            analysis_id="generalised-analysis",
            privacy_mode=PrivacyMode.GENERALISED,
        )
    )
    evidence = controls.project_evidence(make_evidence("evt-1"), context)

    assert evidence.event_timestamp == BASE_TIME.replace(minute=0)
    assert evidence.collected_at == BASE_TIME.replace(minute=0)
    assert evidence.uid == 1000
    assert evidence.actor is None
    assert evidence.project_id is None
    assert evidence.resource == "path-extension:log"
    assert evidence.source_path == "path-extension:log"
    assert "username" not in evidence.attributes
    assert evidence.raw_data == b""


def test_restricted_mode_defaults_to_temporal_and_entity_features():
    controls = PrivacyControls()
    context = controls.prepare_context(
        CorrelationContext(
            analysis_id="restricted-analysis",
            privacy_mode=PrivacyMode.RESTRICTED,
        )
    )
    evidence = controls.project_evidence(make_evidence("evt-1"), context)

    assert context.permitted_feature_types == ("temporal", "entity")
    assert evidence.actor == "alice"
    assert evidence.resource is None
    assert evidence.event_type == "restricted"
    assert evidence.source == "restricted"
    assert evidence.sha256 == ""
    assert evidence.provenance == {}


def test_generalised_mode_is_applied_through_the_correlation_engine():
    engine = CorrelationEngine(
        scorer=CorrelationScorer(threshold=0.0),
        pseudonymisation_key=TEST_PRIVACY_KEY,
    )
    result = engine.process(
        (
            make_evidence("evt-a"),
            make_evidence(
                "evt-b",
                timestamp=BASE_TIME + timedelta(minutes=20),
            ),
        ),
        CorrelationContext(
            analysis_id="generalised-result",
            privacy_mode=PrivacyMode.GENERALISED,
            minimum_score=0.0,
        ),
    )

    assert result.findings
    assert result.findings[0].tenant_ids[0] != "tenant-a"
    graph_data = result.evidence_graph.model_dump_json()
    assert "alice" not in graph_data
    assert "web-01" not in graph_data
    assert "/srv/private/report.log" not in graph_data
    assert "2026-10-19T10:35" not in graph_data


def test_restricted_mode_only_scores_and_exposes_permitted_features():
    first = make_evidence("evt-1")
    second = make_evidence(
        "evt-2",
        timestamp=BASE_TIME + timedelta(seconds=2),
    )
    engine = CorrelationEngine(
        scorer=CorrelationScorer(threshold=0.0),
    )

    result = engine.process(
        (first, second),
        CorrelationContext(
            analysis_id="restricted-result",
            privacy_mode=PrivacyMode.RESTRICTED,
        ),
    )

    assert result.context.permitted_feature_types == ("temporal", "entity")
    assert result.findings
    assert {
        feature.feature_name
        for finding in result.findings
        for feature in finding.score.features
    } <= {"temporal", "entity"}
    assert all(not finding.provenance for finding in result.findings)
    event_nodes = [
        node
        for node in result.evidence_graph.nodes
        if node.node_type.value == "event"
    ]
    assert event_nodes
    assert all(
        "source_path" not in node.attributes
        and "sha256" not in node.attributes
        and "event_timestamp" in node.attributes
        for node in event_nodes
    )


def test_pseudonymised_cross_tenant_correlation_uses_raw_authorisation():
    engine = CorrelationEngine(
        scorer=CorrelationScorer(threshold=0.0),
        pseudonymisation_key=TEST_PRIVACY_KEY,
    )
    result = engine.process(
        (
            make_evidence("evt-a", tenant_id="tenant-a"),
            make_evidence(
                "evt-b",
                tenant_id="tenant-b",
                timestamp=BASE_TIME + timedelta(seconds=2),
            ),
        ),
        CorrelationContext(
            analysis_id="cross-tenant-pseudonymised",
            allow_cross_tenant=True,
            allowed_tenant_pairs=(("tenant-a", "tenant-b"),),
            privacy_mode=PrivacyMode.PSEUDONYMISED,
        ),
    )

    assert result.findings
    assert result.findings[0].cross_tenant
    assert "tenant-a" not in str(result.findings[0].tenant_ids)
    assert "tenant-b" not in str(result.findings[0].tenant_ids)
    assert "tenant-a" not in str(result.context.allowed_tenant_pairs)


@pytest.mark.parametrize(
    "key",
    [None, "short", "django-insecure-" + ("x" * 40)],
)
def test_pseudonymised_mode_requires_configured_secret_key(
    key: str | None,
):
    engine = CorrelationEngine(pseudonymisation_key=key)
    with pytest.raises(ValueError, match="Django SECRET_KEY"):
        engine.process(
            (),
            CorrelationContext(
                analysis_id="missing-key",
                privacy_mode=PrivacyMode.PSEUDONYMISED,
            ),
        )
