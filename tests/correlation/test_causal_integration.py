from datetime import datetime, timedelta, timezone

from correlation.candidates import CandidateGenerator
from correlation.causal import CausalReasoner
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
        source="test",
        source_path="/var/log/audit.log",
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
            "collection_method": "agent",
        },
    )


def test_candidate_generator_feeds_causal_reasoner():
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
        now + timedelta(seconds=10),
        resource="/srv/app/data.db",
    )

    generator = CandidateGenerator(
        temporal_window_seconds=60.0,
    )

    candidates = generator.generate(
        (
            create,
            read,
        ),
        entities_by_evidence={},
    )

    assert candidates

    candidate = candidates[0]

    reasoner = CausalReasoner()

    context = CorrelationContext(
        analysis_id="integration-test",
        requested_tenants=("tenant-a",),
        allow_cross_tenant=False,
        temporal_window_seconds=60.0,
    )

    result = reasoner.reason(
        candidate=candidate,
        evidence_by_id={
            create.evidence_id: create,
            read.evidence_id: read,
        },
        context=context,
    )

    assert len(result.relationships) == 1
    assert (
        result.relationships[0].relation.value
        == "provides"
    )