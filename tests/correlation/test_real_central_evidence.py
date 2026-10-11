from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from correlation.attributes import AttributeExtractor
from correlation.centralEvidence import CentralEvidenceReader
from correlation.engine import CorrelationEngine
from correlation.entities import EntityExtractor
from correlation.normaliser import EvidenceNormaliser
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule

RUN_REAL_CENTRAL = os.getenv("RUN_REAL_CENTRAL", "").lower() in {
    "1",
    "true",
    "yes",
}

CENTRAL_DB_PATH = Path(
    os.getenv(
        "CENTRAL_DB_PATH",
        "storage/evidence.db",
    )
)

pytestmark = pytest.mark.skipif(
    not RUN_REAL_CENTRAL,
    reason=(
        "Real Central evidence tests disabled. " "Set RUN_REAL_CENTRAL=1 to run them."
    ),
)


@pytest.fixture
def reader() -> CentralEvidenceReader:
    return CentralEvidenceReader(CENTRAL_DB_PATH)


@pytest.fixture
def engine() -> CorrelationEngine:
    return CorrelationEngine(
        normaliser=EvidenceNormaliser(),
        attribute_extractor=AttributeExtractor(),
        entity_mapper=EntityExtractor(),
        relationship_mapper=RelationshipMapper(),
        rules=[
            SameTenantTemporalRule(window_seconds=10),
        ],
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _central_counts() -> tuple[int, int]:
    with sqlite3.connect(CENTRAL_DB_PATH) as connection:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM evidence_events"
        ).fetchone()[0]

        record_count = connection.execute(
            "SELECT COUNT(*) FROM evidence_records"
        ).fetchone()[0]

    return event_count, record_count


def test_real_central_database_contains_evidence():
    assert (
        CENTRAL_DB_PATH.exists()
    ), f"Central database does not exist: {CENTRAL_DB_PATH}"

    event_count, record_count = _central_counts()

    assert event_count > 0, "Central evidence_events table is empty"
    assert record_count > 0, "Central evidence_records table is empty"


def test_reader_fetches_real_instance_events(reader):
    events = reader.fetch_events(limit=25)

    assert events, "No real instance evidence was returned"

    for event in events:
        assert event.event_id
        assert event.tenant_id
        assert event.instance_name
        assert event.source
        assert event.event_type
        assert event.timestamp is not None
        assert event.created_at is not None
        assert isinstance(event.raw_data, bytes)
        assert event.sha256

        assert _sha256(event.raw_data) == event.sha256


def test_reader_fetches_real_host_records(reader):
    records = reader.fetch_records(limit=25)

    assert records, "No real host evidence was returned"

    for record in records:
        assert record.evidence_id
        assert record.source
        assert record.source_path
        assert record.collected_at is not None
        assert isinstance(record.raw_data, bytes)
        assert record.sha256

        assert _sha256(record.raw_data) == record.sha256


def test_real_central_evidence_passes_complete_correlation_pipeline(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=50,
        record_limit=50,
    )

    assert evidence, "No real Central evidence returned"

    result = engine.process(evidence)

    assert result.evidence
    assert result.entities
    assert result.relationships

    evidence_ids = {item.evidence_id for item in result.evidence}

    assert evidence_ids

    for item in result.evidence:
        assert item.evidence_id
        assert item.sha256
        assert item.tenant_id
        assert isinstance(item.raw_data, bytes)

    for finding in result.findings:
        assert finding.evidence_ids
        assert set(finding.evidence_ids).issubset(evidence_ids)


def test_real_central_evidence_preserves_tenant_context(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=100,
        record_limit=100,
    )

    assert evidence

    result = engine.process(evidence)

    assert result.evidence

    for item in result.evidence:
        assert item.tenant_id is not None


def test_real_central_findings_are_tenant_scoped(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=100,
        record_limit=100,
    )

    assert evidence

    result = engine.process(evidence)

    evidence_by_id = {item.evidence_id: item for item in result.evidence}

    for finding in result.findings:
        finding_tenants = {
            evidence_by_id[evidence_id].tenant_id
            for evidence_id in finding.evidence_ids
        }

        assert len(finding_tenants) == 1

        assert finding.tenant_id in finding_tenants


def test_real_central_entities_are_tenant_scoped(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=100,
        record_limit=100,
    )

    assert evidence

    result = engine.process(evidence)

    entities_by_type_and_value = {}

    for entity in result.entities:
        key = (
            entity.entity_type,
            entity.value,
        )

        entities_by_type_and_value.setdefault(
            key,
            [],
        ).append(entity)

    for entities in entities_by_type_and_value.values():
        tenant_ids = {entity.tenant_id for entity in entities}

        if len(tenant_ids) > 1:
            entity_ids = {entity.entity_id for entity in entities}

            assert len(entity_ids) == len(entities)


def test_real_central_provenance_is_preserved(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=50,
        record_limit=50,
    )

    assert evidence

    result = engine.process(evidence)

    for item in result.evidence:
        assert item.provenance

        source_table = item.provenance.get("source_table")

        assert source_table in {
            "evidence_events",
            "evidence_records",
        }

        if source_table == "evidence_events":
            assert item.layer.value == "instance"

        if source_table == "evidence_records":
            assert item.layer.value == "host"


def test_real_central_tenant_a_and_b_do_not_cross_correlate(
    reader,
    engine,
):
    tenant_a = reader.fetch_evidence(
        tenant_id="tenant-a",
        event_limit=25,
        record_limit=25,
    )

    tenant_b = reader.fetch_evidence(
        tenant_id="tenant-b",
        event_limit=25,
        record_limit=25,
    )

    if not tenant_a or not tenant_b:
        pytest.skip("Both tenant-a and tenant-b need real Central evidence")

    combined = tuple(tenant_a) + tuple(tenant_b)

    result = engine.process(combined)

    evidence_by_id = {item.evidence_id: item for item in result.evidence}

    for finding in result.findings:
        tenants = {
            evidence_by_id[evidence_id].tenant_id
            for evidence_id in finding.evidence_ids
        }

        assert len(tenants) == 1


def test_real_central_instance_and_host_layers_are_both_processed(
    reader,
    engine,
):
    evidence = reader.fetch_evidence(
        event_limit=50,
        record_limit=50,
    )

    assert evidence

    result = engine.process(evidence)

    layers = {item.layer.value for item in result.evidence}

    assert "instance" in layers
    assert "host" in layers
