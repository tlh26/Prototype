from datetime import datetime, timezone

from correlation.entities import EntityExtractor
from correlation.models import CanonicalEvidence, EntityType, EvidenceLayer


def make_evidence(**overrides):
    values = {
        "evidence_id": "event-001",
        "tenant_id": "tenant-b",
        "project_id": "tenant-b",
        "instance_name": "web-b",
        "layer": EvidenceLayer.INSTANCE,
        "evidence_type": "authentication",
        "event_type": "SESSION_CREATED",
        "source": "auth.log",
        "source_path": "/var/log/auth.log",
        "event_timestamp": datetime.now(timezone.utc),
        "collected_at": datetime.now(timezone.utc),
        "actor": "root",
        "uid": 0,
        "resource": "/tmp/test.txt",
        "attributes": {
            "process": "sshd",
        },
        "raw_data": b"test",
        "sha256": "a" * 64,
        "agent_id": "agent-web-b",
        "sequence_start": 1,
        "sequence_end": 1,
    }

    values.update(overrides)
    return CanonicalEvidence(**values)


def test_extracts_tenant_entity():
    evidence = make_evidence()

    entities = EntityExtractor().extract(evidence)

    tenant = next(
        entity for entity in entities if entity.entity_type == EntityType.TENANT
    )

    assert tenant.value == "tenant-b"
    assert tenant.tenant_id == "tenant-b"
    assert tenant.evidence_ids == ("event-001",)


def test_extracts_project_entity():
    evidence = make_evidence()

    entities = EntityExtractor().extract(evidence)

    project = next(
        entity for entity in entities if entity.entity_type == EntityType.PROJECT
    )

    assert project.value == "tenant-b"
    assert project.tenant_id == "tenant-b"


def test_extracts_instance_entity():
    evidence = make_evidence()

    entities = EntityExtractor().extract(evidence)

    instance = next(
        entity for entity in entities if entity.entity_type == EntityType.INSTANCE
    )

    assert instance.value == "web-b"
    assert instance.tenant_id == "tenant-b"
    assert instance.instance_name == "web-b"


def test_extracts_user_resource_and_process_entities():
    evidence = make_evidence()

    entities = EntityExtractor().extract(evidence)

    types = {entity.entity_type for entity in entities}

    assert EntityType.USER in types
    assert EntityType.RESOURCE in types
    assert EntityType.PROCESS in types


def test_entity_ids_are_deterministic():
    evidence1 = make_evidence(evidence_id="event-001")
    evidence2 = make_evidence(evidence_id="event-002")

    entities1 = EntityExtractor().extract(evidence1)
    entities2 = EntityExtractor().extract(evidence2)

    ids1 = {entity.entity_id for entity in entities1}

    ids2 = {entity.entity_id for entity in entities2}

    assert ids1 == ids2


def test_same_actor_in_different_tenants_isolated():
    extractor = EntityExtractor()

    tenant_a = make_evidence(
        evidence_id="event-a",
        tenant_id="tenant-a",
        project_id="tenant-a",
        instance_name="web-a",
        actor="root",
    )

    tenant_b = make_evidence(
        evidence_id="event-b",
        tenant_id="tenant-b",
        project_id="tenant-b",
        instance_name="web-b",
        actor="root",
    )

    entities_a = extractor.extract(tenant_a)
    entities_b = extractor.extract(tenant_b)

    user_a = next(
        entity for entity in entities_a if entity.entity_type == EntityType.USER
    )

    user_b = next(
        entity for entity in entities_b if entity.entity_type == EntityType.USER
    )

    assert user_a.value == "root"
    assert user_b.value == "root"

    assert user_a.entity_id != user_b.entity_id
