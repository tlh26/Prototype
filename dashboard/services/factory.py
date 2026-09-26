from __future__ import annotations

from functools import lru_cache

from django.conf import settings

from correlation.attributes import AttributeExtractor
from correlation.centralEvidence import PostgreSQLCorrelationSource
from correlation.engine import CorrelationEngine
from correlation.entities import EntityExtractor
from correlation.normaliser import EvidenceNormaliser
from correlation.relationships import RelationshipMapper
from correlation.rules import SameTenantTemporalRule

from .correlation import CorrelationService


@lru_cache(maxsize=1)
def build_correlation_source() -> PostgreSQLCorrelationSource:
    """
    Construct the read-only authoritative PostgreSQL evidence source.
    """

    return PostgreSQLCorrelationSource()


@lru_cache(maxsize=1)
def build_correlation_engine() -> CorrelationEngine:
    """
    Construct the single authoritative correlation engine.

    All correlation behaviour remains in the correlation package.
    """

    return CorrelationEngine(
        normaliser=EvidenceNormaliser(),
        attribute_extractor=AttributeExtractor(),
        entity_mapper=EntityExtractor(),
        relationship_mapper=RelationshipMapper(),
        rules=[
            SameTenantTemporalRule(
                window_seconds=settings.DASHBOARD_RULE_WINDOW_SECONDS,
            )
        ],
    )


@lru_cache(maxsize=1)
def build_correlation_service() -> CorrelationService:
    """
    Construct the dashboard-facing correlation service.
    """

    return CorrelationService(
        source=build_correlation_source(),
        engine=build_correlation_engine(),
        evidence_limit=settings.DASHBOARD_EVIDENCE_LIMIT,
    )