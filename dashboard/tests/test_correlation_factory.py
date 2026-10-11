from __future__ import annotations

from correlation.engine import CorrelationEngine

from dashboard.services.factory import (
    build_correlation_engine,
    build_correlation_service,
    build_correlation_source,
)


def test_correlation_source_constructs():
    source = build_correlation_source()

    assert source is not None


def test_correlation_engine_constructs():
    engine = build_correlation_engine()

    assert isinstance(engine, CorrelationEngine)
    assert len(engine.rules) == 1


def test_correlation_service_constructs():
    service = build_correlation_service()

    assert service is not None
    assert service.source is build_correlation_source()
    assert service.engine is build_correlation_engine()
