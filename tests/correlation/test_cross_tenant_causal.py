from datetime import datetime, timedelta, timezone

from correlation.engine import CorrelationEngine
from correlation.models import (
    CanonicalEvidence,
    CorrelationContext,
    EvidenceLayer,
)


UTC = timezone.utc


def evidence(
    evidence_id,
    event_type,
    timestamp,
    tenant_id,
    resource,
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
        raw_data=b"cross-tenant-test",
        sha256="b" * 64,
        agent_id=f"agent-{tenant_id}",
        provenance={
            "source": "auditd",
        },
    )


def test_cross_tenant_causal_relationship_is_preserved():
    now = datetime.now(UTC)

    tenant_a_create = evidence(
        "tenant-a-create",
        "RESOURCE_CREATE",
        now,
        "tenant-a",
        "/shared/data.db",
    )

    tenant_b_read = evidence(
        "tenant-b-read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        "tenant-b",
        "/shared/data.db",
    )

    context = CorrelationContext(
        analysis_id="cross-tenant-causal",
        requested_tenants=(
            "tenant-a",
            "tenant-b",
        ),
        allow_cross_tenant=True,
        allowed_tenant_pairs=(
            (
                "tenant-a",
                "tenant-b",
            ),
        ),
        temporal_window_seconds=60.0,
        minimum_score=0.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            tenant_a_create,
            tenant_b_read,
        ),
        context=context,
    )

    assert result.findings

    finding = result.findings[0]

    assert finding.cross_tenant is True

    assert finding.causal_relationships

    causal = finding.causal_relationships[0]

    assert causal.relation.value == "provides"

    assert causal.cross_tenant is True

    assert set(causal.tenant_ids) == {
        "tenant-a",
        "tenant-b",
    }

def test_cross_tenant_causal_reasoning_is_blocked_when_policy_denies():
    now = datetime.now(UTC)

    tenant_a_create = evidence(
        "tenant-a-create",
        "RESOURCE_CREATE",
        now,
        "tenant-a",
        "/shared/data.db",
    )

    tenant_b_read = evidence(
        "tenant-b-read",
        "RESOURCE_READ",
        now + timedelta(seconds=5),
        "tenant-b",
        "/shared/data.db",
    )

    context = CorrelationContext(
        analysis_id="cross-tenant-denied",
        requested_tenants=(
            "tenant-a",
            "tenant-b",
        ),
        allow_cross_tenant=False,
        temporal_window_seconds=60.0,
        minimum_score=0.0,
    )

    engine = CorrelationEngine()

    result = engine.process(
        (
            tenant_a_create,
            tenant_b_read,
        ),
        context=context,
    )

    assert result.findings == ()
    assert result.policy_denied_count >= 1