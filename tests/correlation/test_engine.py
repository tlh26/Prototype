from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from correlation.correlationFinding import (
    CorrelationFinding,
    FindingSeverity,
)
from correlation.engine import CorrelationEngine
from correlation.models import (
    CanonicalEvidence,
    EntityType,
    EvidenceEntity,
    EvidenceLayer,
    EvidenceRelationship,
    RelationshipType,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def make_event(
    *,
    event_id: str = "event-001",
    tenant_id: str = "tenant-a",
    instance_name: str = "web-a",
    timestamp: datetime | None = None,
):
    """Create a minimal authoritative instance-style evidence object."""

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return SimpleNamespace(
        event_id=event_id,
        tenant_id=tenant_id,
        instance_name=instance_name,
        evidence_type=SimpleNamespace(value="authentication"),
        event_type=SimpleNamespace(value="LOGIN"),
        timestamp=timestamp,
        created_at=timestamp,
        actor="root",
        uid=0,
        resource="/login",
        source="auth.log",
        source_path="/var/log/auth.log",
        details={"method": "password"},
        sequence=1,
        agent_id="agent-test",
        raw_data=b"test evidence",
        sha256="test-sha256",
    )


def make_canonical(
    *,
    evidence_id: str = "event-001",
    tenant_id: str = "tenant-a",
    instance_name: str = "web-a",
    timestamp: datetime | None = None,
) -> CanonicalEvidence:
    """Create canonical evidence for isolated engine tests."""

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return CanonicalEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        project_id=tenant_id,
        instance_name=instance_name,
        layer=EvidenceLayer.INSTANCE,
        evidence_type="authentication",
        event_type="LOGIN",
        source="auth.log",
        source_path="/var/log/auth.log",
        event_timestamp=timestamp,
        collected_at=timestamp,
        actor="root",
        uid=0,
        resource="/login",
        attributes={"method": "password"},
        raw_data=b"test evidence",
        sha256="test-sha256",
        agent_id="agent-test",
        sequence_start=1,
        sequence_end=1,
        provenance={"source_table": "evidence_events"},
    )


class FakeNormaliser:
    """Controlled normaliser for engine unit tests."""

    def normalise_event(self, evidence):
        return make_canonical(
            evidence_id=evidence.event_id,
            tenant_id=evidence.tenant_id,
            instance_name=evidence.instance_name,
            timestamp=evidence.timestamp,
        )

    def normalise_record(self, evidence):
        return make_canonical(
            evidence_id=evidence.evidence_id,
            tenant_id=evidence.tenant_id,
            instance_name=evidence.instance_name,
            timestamp=evidence.collected_at,
        )


class FakeAttributeExtractor:
    def __init__(self):
        self.calls = []

    def extract(self, evidence):
        self.calls.append(evidence.evidence_id)
        return {
            "tenant_id": evidence.tenant_id,
            "instance_name": evidence.instance_name,
        }


class FakeEntityMapper:
    def __init__(self):
        self.calls = []

    def extract(self, evidence):
        self.calls.append(evidence.evidence_id)

        entity = EvidenceEntity(
            entity_id=f"instance:{evidence.instance_name}",
            entity_type=EntityType.INSTANCE,
            value=evidence.instance_name,
            tenant_id=evidence.tenant_id,
            instance_name=evidence.instance_name,
            evidence_ids=(evidence.evidence_id,),
        )

        return (entity,)


class FakeRelationshipMapper:
    def __init__(self):
        self.calls = []

    def map(self, evidence, entities):
        self.calls.append(
            (
                evidence.evidence_id,
                tuple(entity.entity_id for entity in entities),
            )
        )

        return (
            EvidenceRelationship(
                relationship_id=f"relationship:{evidence.evidence_id}",
                source_entity_id=entities[0].entity_id,
                relationship_type=RelationshipType.BELONGS_TO,
                target_entity_id="tenant:tenant-a",
                evidence_ids=(evidence.evidence_id,),
            ),
        )


class FakeRule:
    """Deterministic rule used to verify engine rule orchestration."""

    rule_id = "test-rule"
    rule_version = "1.0"

    def __init__(self):
        self.calls = []

    def evaluate(self, first, second):
        self.calls.append((first.evidence_id, second.evidence_id))

        if first.tenant_id != second.tenant_id:
            return None

        return CorrelationFinding(
            finding_id=f"test-rule:{first.evidence_id}:{second.evidence_id}",
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            title="Test correlation",
            description="Test finding generated by fake rule.",
            severity=FindingSeverity.INFO,
            tenant_id=first.tenant_id,
            evidence_ids=(
                first.evidence_id,
                second.evidence_id,
            ),
            first_timestamp=min(
                first.event_timestamp,
                second.event_timestamp,
            ),
            last_timestamp=max(
                first.event_timestamp,
                second.event_timestamp,
            ),
            attributes={},
            created_at=max(
                first.event_timestamp,
                second.event_timestamp,
            ),
        )


# ---------------------------------------------------------------------------
# Engine construction
# ---------------------------------------------------------------------------


def make_engine(
    *,
    rule=None,
    attribute_extractor=None,
    entity_mapper=None,
    relationship_mapper=None,
):
    return CorrelationEngine(
        normaliser=FakeNormaliser(),
        attribute_extractor=attribute_extractor or FakeAttributeExtractor(),
        entity_mapper=entity_mapper or FakeEntityMapper(),
        relationship_mapper=relationship_mapper or FakeRelationshipMapper(),
        rules=[rule or FakeRule()],
    )


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def test_engine_normalises_instance_event():

    engine = make_engine()

    event = make_event(event_id="event-001")

    result = engine.process([event])

    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_id == "event-001"
    assert result.evidence[0].tenant_id == "tenant-a"
    assert result.evidence[0].layer == EvidenceLayer.INSTANCE


def test_engine_normalises_event_using_event_id():

    engine = make_engine()

    event = make_event(event_id="event-123")

    result = engine.process([event])

    assert result.evidence[0].evidence_id == "event-123"


# ---------------------------------------------------------------------------
# Attribute extraction
# ---------------------------------------------------------------------------


def test_engine_invokes_attribute_extractor():

    extractor = FakeAttributeExtractor()

    engine = make_engine(
        attribute_extractor=extractor,
    )

    event = make_event(event_id="event-001")

    engine.process([event])

    assert extractor.calls == ["event-001"]


def test_engine_processes_attributes_without_mutating_canonical_evidence():

    extractor = FakeAttributeExtractor()

    engine = make_engine(
        attribute_extractor=extractor,
    )

    event = make_event(event_id="event-001")

    result = engine.process([event])

    evidence = result.evidence[0]

    assert evidence.evidence_id == "event-001"
    assert evidence.tenant_id == "tenant-a"


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------


def test_engine_invokes_entity_mapper():

    mapper = FakeEntityMapper()

    engine = make_engine(
        entity_mapper=mapper,
    )

    event = make_event(event_id="event-001")

    result = engine.process([event])

    assert mapper.calls == ["event-001"]
    assert len(result.entities) == 1
    assert result.entities[0].entity_id == "instance:web-a"


# ---------------------------------------------------------------------------
# Relationship mapping
# ---------------------------------------------------------------------------


def test_engine_invokes_relationship_mapper():

    mapper = FakeRelationshipMapper()

    engine = make_engine(
        relationship_mapper=mapper,
    )

    event = make_event(event_id="event-001")

    result = engine.process([event])

    assert len(mapper.calls) == 1
    assert mapper.calls[0][0] == "event-001"

    assert len(result.relationships) == 1
    assert result.relationships[0].relationship_id == "relationship:event-001"


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def test_engine_evaluates_each_pair_once():

    rule = FakeRule()

    engine = make_engine(rule=rule)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    events = [
        make_event(
            event_id="event-001",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            timestamp=base + timedelta(seconds=2),
        ),
        make_event(
            event_id="event-003",
            timestamp=base + timedelta(seconds=4),
        ),
    ]

    result = engine.process(events)

    assert rule.calls == [
        ("event-001", "event-002"),
        ("event-001", "event-003"),
        ("event-002", "event-003"),
    ]

    assert len(result.findings) == 3


def test_engine_does_not_compare_an_evidence_item_with_itself():

    rule = FakeRule()

    engine = make_engine(rule=rule)

    event = make_event(event_id="event-001")

    result = engine.process([event])

    assert rule.calls == []
    assert result.findings == ()


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_engine_allows_rule_to_reject_cross_tenant_evidence():

    rule = FakeRule()

    engine = make_engine(rule=rule)

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    first = make_event(
        event_id="event-a",
        tenant_id="tenant-a",
        timestamp=base,
    )

    second = make_event(
        event_id="event-b",
        tenant_id="tenant-b",
        timestamp=base + timedelta(seconds=1),
    )

    result = engine.process([first, second])

    assert rule.calls == [
        ("event-a", "event-b"),
    ]

    assert result.findings == ()


# ---------------------------------------------------------------------------
# Finding deduplication
# ---------------------------------------------------------------------------


def test_engine_deduplicates_findings_by_finding_id():

    class DuplicateRule:
        rule_id = "duplicate-rule"
        rule_version = "1.0"

        def evaluate(self, first, second):
            timestamp = first.event_timestamp

            return CorrelationFinding(
                finding_id="duplicate-finding",
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                title="Duplicate",
                description="Duplicate test finding.",
                severity=FindingSeverity.INFO,
                tenant_id=first.tenant_id,
                evidence_ids=(
                    first.evidence_id,
                    second.evidence_id,
                ),
                first_timestamp=timestamp,
                last_timestamp=timestamp,
                attributes={},
                created_at=timestamp,
            )

    engine = CorrelationEngine(
        normaliser=FakeNormaliser(),
        attribute_extractor=FakeAttributeExtractor(),
        entity_mapper=FakeEntityMapper(),
        relationship_mapper=FakeRelationshipMapper(),
        rules=[DuplicateRule()],
    )

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    events = [
        make_event(
            event_id="event-001",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            timestamp=base + timedelta(seconds=1),
        ),
        make_event(
            event_id="event-003",
            timestamp=base + timedelta(seconds=2),
        ),
    ]

    result = engine.process(events)

    assert len(result.findings) == 1
    assert result.findings[0].finding_id == "duplicate-finding"


# ---------------------------------------------------------------------------
# Entity deduplication
# ---------------------------------------------------------------------------


def test_engine_merges_duplicate_entities_and_preserves_evidence_ids():

    engine = make_engine()

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    events = [
        make_event(
            event_id="event-001",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            timestamp=base + timedelta(seconds=1),
        ),
    ]

    result = engine.process(events)

    assert len(result.entities) == 1

    entity = result.entities[0]

    assert entity.entity_id == "instance:web-a"
    assert entity.evidence_ids == (
        "event-001",
        "event-002",
    )


# ---------------------------------------------------------------------------
# Relationship deduplication
# ---------------------------------------------------------------------------


def test_engine_merges_duplicate_relationships_and_preserves_evidence_ids():

    engine = make_engine()

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    events = [
        make_event(
            event_id="event-001",
            timestamp=base,
        ),
        make_event(
            event_id="event-002",
            timestamp=base + timedelta(seconds=1),
        ),
    ]

    result = engine.process(events)

    assert len(result.relationships) == 2

    relationship_ids = {
        relationship.relationship_id for relationship in result.relationships
    }

    assert relationship_ids == {
        "relationship:event-001",
        "relationship:event-002",
    }


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


def test_engine_handles_empty_input():

    engine = make_engine()

    result = engine.process([])

    assert result.evidence == ()
    assert result.entities == ()
    assert result.relationships == ()
    assert result.findings == ()
