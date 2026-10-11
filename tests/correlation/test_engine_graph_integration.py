
from datetime import datetime, timezone

from correlation.engine import CorrelationEngine
from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    EvidenceLayer,
)


def make_event(evidence_id, tenant_id, event_type, timestamp):
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
        attributes={"action": event_type},
        raw_data=b"test",
        sha256="b" * 64,
        provenance={},
    )


def test_engine_returns_graph_for_analysis():
    now = datetime.now(timezone.utc)
    evidence = (
        make_event("event-a", "tenant-a", "LOGIN_SUCCESS", now),
        make_event("event-b", "tenant-a", "SESSION_CREATED", now),
    )
    context = CorrelationContext(
        analysis_id="analysis:graph-integration",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        temporal_window_seconds=60,
        minimum_score=0.0,
    )

    result = CorrelationEngine().process(evidence, context=context)

    assert result.evidence_graph is not None
    assert result.evidence_graph.analysis_id == context.analysis_id
    assert result.metadata["graph_node_count"] == result.evidence_graph.node_count
    assert result.metadata["graph_edge_count"] == result.evidence_graph.edge_count

