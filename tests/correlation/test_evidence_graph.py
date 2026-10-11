
from datetime import datetime, timezone

from correlation.graph import EvidenceGraphBuilder
from correlation.models import (
    CanonicalEvidence,
    CausalLink,
    CausalRelation,
    CorrelationContext,
    CorrelationFeature,
    CorrelationFinding,
    CorrelationScore,
    EvidenceLayer,
    FindingSeverity,
    FindingStatus,
    GraphEdgeType,
    PrivacyMode,
)


def make_evidence(evidence_id, tenant_id, event_type, timestamp, resource=None):
    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name=f"web-{tenant_id}",
        layer=EvidenceLayer.INSTANCE,
        evidence_type="audit",
        event_type=event_type,
        source="test",
        event_timestamp=timestamp,
        collected_at=timestamp,
        resource=resource,
        attributes={},
        raw_data=b"test",
        sha256="a" * 64,
        provenance={},
    )


def make_finding(evidence_ids, causal_relationships=()):
    tenant_ids = tuple(
        sorted(
            {
                "tenant-a" if evidence_id.endswith("a") else "tenant-b"
                for evidence_id in evidence_ids
            }
        )
    )
    score = CorrelationScore(
        value=0.9,
        threshold=0.7,
        passed=True,
        features=(
            CorrelationFeature(
                feature_name="temporal",
                value=0.9,
                weight=1.0,
                contribution=0.9,
                explanation="Events occurred close together.",
                evidence_ids=evidence_ids,
            ),
        ),
        weight_sum=1.0,
        valid_feature_count=1,
        explanation="Test score.",
    )
    return CorrelationFinding(
        finding_id="finding:test",
        candidate_id="candidate:test",
        analysis_id="analysis:test",
        tenant_ids=tenant_ids,
        cross_tenant=len(tenant_ids) > 1,
        evidence_ids=evidence_ids,
        score=score,
        explanation="Test finding.",
        status=FindingStatus.CONFIRMED,
        severity=FindingSeverity.INFO,
        privacy_mode=PrivacyMode.RAW,
        causal_relationship_ids=tuple(
            link.relationship_id for link in causal_relationships
        ),
        causal_relationships=causal_relationships,
        policy_allowed=True,
    )


def test_graph_contains_events_tenants_and_correlation_edge():
    now = datetime.now(timezone.utc)
    evidence = {
        "event-a": make_evidence("event-a", "tenant-a", "LOGIN_SUCCESS", now),
        "event-b": make_evidence("event-b", "tenant-b", "SESSION_CREATED", now),
    }
    finding = make_finding(("event-a", "event-b"))

    graph = EvidenceGraphBuilder().build(
        analysis_id="analysis:test",
        evidence_by_id=evidence,
        entities_by_evidence={},
        relationships=(),
        findings=(finding,),
    )

    node_ids = {node.node_id for node in graph.nodes}
    edge_types = {edge.edge_type for edge in graph.edges}

    assert "event:event-a" in node_ids
    assert "event:event-b" in node_ids
    assert "tenant:tenant-a" in node_ids
    assert "tenant:tenant-b" in node_ids
    assert GraphEdgeType.CORRELATED_WITH in edge_types
    assert graph.metadata["evidence_count"] == 2


def test_causal_edge_is_distinct_from_correlation_edge():
    now = datetime.now(timezone.utc)
    evidence = {
        "event-a": make_evidence("event-a", "tenant-a", "LOGIN_SUCCESS", now),
        "event-b": make_evidence("event-b", "tenant-a", "SESSION_CREATED", now),
    }
    link = CausalLink(
        relationship_id="causal:test",
        relation=CausalRelation.ENABLES,
        source_evidence_id="event-a",
        target_evidence_id="event-b",
        source_action="LOGIN_SUCCESS",
        target_action="SESSION_CREATED",
        evidence_ids=("event-a", "event-b"),
        tenant_ids=("tenant-a",),
        cross_tenant=False,
        temporal_delta_seconds=1.0,
        confidence=0.9,
        explanation="Successful login enables session creation.",
    )
    finding = make_finding(("event-a", "event-b"), (link,))

    graph = EvidenceGraphBuilder().build(
        analysis_id="analysis:test",
        evidence_by_id=evidence,
        entities_by_evidence={},
        relationships=(),
        findings=(finding,),
    )

    assert any(
        edge.edge_type == GraphEdgeType.CORRELATED_WITH
        for edge in graph.edges
    )
    assert any(
        edge.edge_type == GraphEdgeType.ENABLES
        and edge.source_node_id == "event:event-a"
        and edge.target_node_id == "event:event-b"
        for edge in graph.edges
    )


def test_unreferenced_evidence_is_not_added_to_graph():
    now = datetime.now(timezone.utc)
    evidence = {
        "event-a": make_evidence("event-a", "tenant-a", "LOGIN_SUCCESS", now),
        "event-b": make_evidence("event-b", "tenant-a", "SESSION_CREATED", now),
        "event-c": make_evidence("event-c", "tenant-c", "FILE_READ", now),
    }
    finding = make_finding(("event-a", "event-b"))

    graph = EvidenceGraphBuilder().build(
        analysis_id="analysis:test",
        evidence_by_id=evidence,
        entities_by_evidence={},
        relationships=(),
        findings=(finding,),
    )

    node_ids = {node.node_id for node in graph.nodes}
    assert "event:event-c" not in node_ids
    assert graph.metadata["evidence_count"] == 2


def test_denied_finding_does_not_contribute_graph_evidence():
    now = datetime.now(timezone.utc)
    evidence = {
        "event-a": make_evidence("event-a", "tenant-a", "LOGIN_SUCCESS", now),
        "event-b": make_evidence("event-b", "tenant-b", "SESSION_CREATED", now),
    }
    finding = make_finding(("event-a", "event-b")).model_copy(
        update={"policy_allowed": False}
    )

    graph = EvidenceGraphBuilder().build(
        analysis_id="analysis:test",
        evidence_by_id=evidence,
        entities_by_evidence={},
        relationships=(),
        findings=(finding,),
    )

    assert graph.nodes == ()
    assert graph.edges == ()
