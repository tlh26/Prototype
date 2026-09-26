from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from correlation.attributes import AttributeExtractor
from correlation.correlationFinding import FindingSeverity
from correlation.engine import CorrelationEngine
from correlation.entities import EntityExtractor
from correlation.models import EvidenceLayer, EntityType, RelationshipType
from correlation.normaliser import EvidenceNormaliser
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule
from correlation.timeline import EvidenceTimeline

# ---------------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------------


def make_event(
    *,
    event_id: str,
    tenant_id: str,
    instance_name: str,
    timestamp: datetime,
    actor: str = "root",
    resource: str = "/tmp/evidence/test.txt",
    sequence: int = 1,
):
    """
    Create an authoritative instance evidence object matching the
    fields consumed by EvidenceNormaliser.
    """

    return SimpleNamespace(
        event_id=event_id,
        tenant_id=tenant_id,
        instance_name=instance_name,
        evidence_type=SimpleNamespace(value="filesystem"),
        event_type=SimpleNamespace(value="FILE_CREATE"),
        timestamp=timestamp,
        created_at=timestamp + timedelta(milliseconds=100),
        actor=actor,
        uid=0,
        resource=resource,
        source="filesystem",
        source_path="/tmp/evidence",
        details={
            "operation": "create",
            "filename": "test.txt",
        },
        sequence=sequence,
        agent_id=f"agent-{instance_name}",
        raw_data=f"{event_id}:raw".encode(),
        sha256=f"sha256-{event_id}",
    )


def build_engine(
    *,
    window_seconds: int = 10,
) -> CorrelationEngine:

    return CorrelationEngine(
        normaliser=EvidenceNormaliser(),
        attribute_extractor=AttributeExtractor(),
        entity_mapper=EntityExtractor(),
        relationship_mapper=RelationshipMapper(),
        rules=[
            SameTenantTemporalRule(
                window_seconds=window_seconds,
            )
        ],
    )


# ---------------------------------------------------------------------------
# Complete pipeline
# ---------------------------------------------------------------------------


def test_real_correlation_pipeline_produces_complete_result():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
            sequence=1,
        ),
        make_event(
            event_id="event-002",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base + timedelta(seconds=5),
            sequence=2,
        ),
    ]

    engine = build_engine()

    result = engine.process(events)

    # --------------------------------------------------------------
    # Canonical evidence
    # --------------------------------------------------------------

    assert len(result.evidence) == 2

    assert result.evidence[0].layer == EvidenceLayer.INSTANCE
    assert result.evidence[0].tenant_id == "tenant-a"

    assert result.evidence[1].layer == EvidenceLayer.INSTANCE
    assert result.evidence[1].tenant_id == "tenant-a"

    # --------------------------------------------------------------
    # Entities
    # --------------------------------------------------------------

    assert result.entities

    entity_types = {entity.entity_type for entity in result.entities}

    assert EntityType.TENANT in entity_types
    assert EntityType.PROJECT in entity_types
    assert EntityType.INSTANCE in entity_types
    assert EntityType.USER in entity_types
    assert EntityType.RESOURCE in entity_types

    # --------------------------------------------------------------
    # Relationships
    # --------------------------------------------------------------

    assert result.relationships

    relationship_types = {
        relationship.relationship_type for relationship in result.relationships
    }

    assert RelationshipType.BELONGS_TO in relationship_types
    assert RelationshipType.ACTED_ON in relationship_types
    assert RelationshipType.OCCURRED_ON in relationship_types

    # --------------------------------------------------------------
    # Findings
    # --------------------------------------------------------------

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.rule_id == "same-tenant-temporal"
    assert finding.rule_version == "1.0"
    assert finding.tenant_id == "tenant-a"
    assert finding.severity == FindingSeverity.INFO

    assert finding.evidence_ids == (
        "event-001",
        "event-002",
    )


# ---------------------------------------------------------------------------
# Temporal rule integration
# ---------------------------------------------------------------------------


def test_same_tenant_events_within_window_correlate():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            tenant_id="tenant-a",
            instance_name="api-a",
            timestamp=base + timedelta(seconds=5),
        ),
    ]

    engine = build_engine(window_seconds=10)

    result = engine.process(events)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.tenant_id == "tenant-a"
    assert finding.evidence_ids == (
        "event-001",
        "event-002",
    )


def test_same_tenant_events_outside_window_do_not_correlate():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            tenant_id="tenant-a",
            instance_name="api-a",
            timestamp=base + timedelta(seconds=11),
        ),
    ]

    engine = build_engine(window_seconds=10)

    result = engine.process(events)

    assert result.findings == ()


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_cross_tenant_events_do_not_correlate():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="tenant-a-event",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
            actor="root",
        ),
        make_event(
            event_id="tenant-b-event",
            tenant_id="tenant-b",
            instance_name="web-b",
            timestamp=base + timedelta(seconds=2),
            actor="root",
        ),
    ]

    engine = build_engine(window_seconds=10)

    result = engine.process(events)

    assert result.findings == ()


def test_same_actor_across_tenants_does_not_create_correlation():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-a",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
            actor="root",
        ),
        make_event(
            event_id="event-b",
            tenant_id="tenant-b",
            instance_name="web-b",
            timestamp=base + timedelta(seconds=1),
            actor="root",
        ),
    ]

    engine = build_engine()

    result = engine.process(events)

    assert result.findings == ()


# ---------------------------------------------------------------------------
# Entity tenant isolation
# ---------------------------------------------------------------------------


def test_identical_actor_values_in_different_tenants_remain_distinct_entities():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-a",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
            actor="root",
        ),
        make_event(
            event_id="event-b",
            tenant_id="tenant-b",
            instance_name="web-b",
            timestamp=base,
            actor="root",
        ),
    ]

    engine = build_engine()

    result = engine.process(events)

    user_entities = [
        entity for entity in result.entities if entity.entity_type == EntityType.USER
    ]

    assert len(user_entities) == 2

    assert {entity.tenant_id for entity in user_entities} == {
        "tenant-a",
        "tenant-b",
    }

    assert len({entity.entity_id for entity in user_entities}) == 2


# ---------------------------------------------------------------------------
# Entity evidence traceability
# ---------------------------------------------------------------------------


def test_entities_retain_supporting_evidence_ids():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base + timedelta(seconds=1),
        ),
    ]

    engine = build_engine()

    result = engine.process(events)

    instance_entities = [
        entity
        for entity in result.entities
        if entity.entity_type == EntityType.INSTANCE
    ]

    assert len(instance_entities) == 1

    instance = instance_entities[0]

    assert instance.value == "web-a"

    assert instance.evidence_ids == (
        "event-001",
        "event-002",
    )


# ---------------------------------------------------------------------------
# Relationship traceability
# ---------------------------------------------------------------------------


def test_relationships_retain_supporting_evidence_ids():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event = make_event(
        event_id="event-001",
        tenant_id="tenant-a",
        instance_name="web-a",
        timestamp=base,
    )

    engine = build_engine()

    result = engine.process([event])

    assert result.relationships

    for relationship in result.relationships:
        assert relationship.evidence_ids == ("event-001",)


# ---------------------------------------------------------------------------
# Timeline integration
# ---------------------------------------------------------------------------


def test_timeline_orders_canonical_evidence_by_event_timestamp():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            event_id="event-003",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base + timedelta(seconds=30),
        ),
        make_event(
            event_id="event-001",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            tenant_id="tenant-a",
            instance_name="web-a",
            timestamp=base + timedelta(seconds=10),
        ),
    ]

    engine = build_engine()

    result = engine.process(events)

    timeline = EvidenceTimeline()

    entries = timeline.build(list(result.evidence))

    assert [entry.evidence_id for entry in entries] == [
        "event-001",
        "event-002",
        "event-003",
    ]


def test_timeline_excludes_canonical_evidence_without_event_timestamp():

    engine = build_engine()

    # Directly construct host-style canonical evidence.
    from correlation.models import CanonicalEvidence

    evidence = CanonicalEvidence(
        evidence_id="host-001",
        tenant_id="tenant-a",
        project_id="tenant-a",
        instance_name="web-a",
        layer=EvidenceLayer.HOST,
        evidence_type="FORENSIC_RECORD",
        event_type="AUDIT",
        source="auditd",
        source_path="/var/log/audit/audit.log",
        event_timestamp=None,
        collected_at=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        raw_data=b"audit event",
        sha256="host-sha256",
        provenance={
            "source_table": "evidence_records",
        },
    )

    timeline = EvidenceTimeline()

    entries = timeline.build([evidence])

    assert entries == ()


# ---------------------------------------------------------------------------
# Mixed layer integration
# ---------------------------------------------------------------------------


def test_instance_and_host_canonical_evidence_can_coexist():

    base = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    instance_event = make_event(
        event_id="instance-001",
        tenant_id="tenant-a",
        instance_name="web-a",
        timestamp=base,
    )

    engine = build_engine()

    result = engine.process([instance_event])

    assert len(result.evidence) == 1
    assert result.evidence[0].layer == EvidenceLayer.INSTANCE

    # The engine should preserve the evidence layer rather than
    # converting everything into an instance representation.
    assert result.evidence[0].evidence_id == "instance-001"
