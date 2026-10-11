from __future__ import annotations

import os

import pytest

from correlation.centralEvidence import PostgreSQLCorrelationSource
from correlation.engine import CorrelationEngine
from correlation.attributes import AttributeExtractor
from correlation.entities import EntityExtractor
from correlation.normaliser import EvidenceNormaliser
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_REAL_CENTRAL") != "1",
    reason="Live PostgreSQL correlation test disabled",
)


def build_engine() -> CorrelationEngine:
    return CorrelationEngine(
        normaliser=EvidenceNormaliser(),
        attribute_extractor=AttributeExtractor(),
        entity_mapper=EntityExtractor(),
        relationship_mapper=RelationshipMapper(),
        rules=[
            SameTenantTemporalRule(
                window_seconds=10,
            )
        ],
    )


@pytest.fixture
def source() -> PostgreSQLCorrelationSource:
    return PostgreSQLCorrelationSource()


@pytest.fixture
def engine() -> CorrelationEngine:
    return build_engine()
