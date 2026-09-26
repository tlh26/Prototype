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
from dashboard.services.evidence import EvidenceService
from .correlation import CorrelationService
from correlation.timeline import EvidenceTimeline
from dashboard.services.timeline import TimelineService
from dashboard.services.tenants import TenantService
from dashboard.services.overview import OverviewService


def _setting(name: str, default):
    """
    Read a Django setting when Django is configured.

    The fallback keeps the correlation composition usable from standalone
    tests and scripts that do not initialise Django.
    """

    try:
        return getattr(settings, name)
    except Exception:
        return default


@lru_cache(maxsize=1)
def build_correlation_source() -> PostgreSQLCorrelationSource:
    """
    Construct the read-only authoritative PostgreSQL evidence source.
    """

    return PostgreSQLCorrelationSource()


@lru_cache(maxsize=1)
def build_correlation_engine() -> CorrelationEngine:
    """
    Construct the authoritative correlation engine.

    All correlation behaviour remains inside the correlation package.
    """

    window_seconds = _setting(
        "DASHBOARD_RULE_WINDOW_SECONDS",
        10,
    )

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


@lru_cache(maxsize=1)
def build_correlation_service() -> CorrelationService:
    """
    Construct the dashboard-facing correlation service.
    """

    evidence_limit = _setting(
        "DASHBOARD_EVIDENCE_LIMIT",
        100,
    )

    return CorrelationService(
        source=build_correlation_source(),
        engine=build_correlation_engine(),
        evidence_limit=evidence_limit,
    )

@lru_cache(maxsize=1)
def build_evidence_service() -> EvidenceService:
    return EvidenceService(
        source=build_correlation_source(),
        evidence_limit=_setting("DASHBOARD_EVIDENCE_LIMIT", 100),
    )

@lru_cache(maxsize=1)
def build_timeline_service() -> TimelineService:
    return TimelineService(
        correlation_service=build_correlation_service(),
        timeline=EvidenceTimeline(),
    )

@lru_cache(maxsize=1)
def build_tenant_service() -> TenantService:
    return TenantService(
        source=build_correlation_source(),
        evidence_limit=_setting("DASHBOARD_EVIDENCE_LIMIT", 100),
    )

@lru_cache(maxsize=1)
def build_overview_service() -> OverviewService:
    return OverviewService(
        tenant_service=build_tenant_service(),
        correlation_service=build_correlation_service(),
        evidence_limit=_setting("DASHBOARD_EVIDENCE_LIMIT", 100),
    )