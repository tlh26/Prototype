# dashboard/services/correlation.py
from __future__ import annotations

from typing import Any
from django.core.paginator import Paginator
from django.http import Http404
from correlation.centralEvidence import PostgreSQLCorrelationSource
from correlation.engine import CorrelationEngine
from dashboard.services.correlationPresentation import (
    CorrelationPresentationAdapter,
)
from correlation.models import CorrelationContext
from time import perf_counter


class CorrelationService:
    """
    Presentation-facing service for running the authoritative
    correlation engine against evidence stored in Central PostgreSQL.

    This service contains no correlation algorithms and no SQL.
    CorrelationEngine remains the authoritative location for
    normalization, entity extraction, relationship mapping,
    candidate generation, scoring, and policy.
    """

    def __init__(
        self,
        *,
        source: PostgreSQLCorrelationSource,
        engine: CorrelationEngine,
        evidence_limit: int = 100,
        presentation_adapter: CorrelationPresentationAdapter | None = None,
    ) -> None:
        self.source = source
        self.engine = engine
        self.evidence_limit = evidence_limit
        self.presentation_adapter = (
            presentation_adapter or CorrelationPresentationAdapter()
        )

    def _fetch_evidence(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ) -> tuple[Any, ...]:
        effective_limit = (
            self.evidence_limit
            if limit is None
            else limit
        )

        if effective_limit <= 0:
            return ()

        events = self.source.fetch_events(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=effective_limit,
        )

        records = self.source.fetch_records(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=effective_limit,
        )

        return events + records

    def evidence(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ) -> tuple[Any, ...]:
        """
        Return canonical evidence suitable for presentation services.

        Evidence is fetched from the authoritative central source and
        normalised through the same CorrelationEngine normalisation
        boundary used by correlation.
        """

        raw_evidence = self._fetch_evidence(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )

        return tuple(
            self.engine.normalise(item)
            for item in raw_evidence
        )

    def correlate(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
        context: CorrelationContext | None = None,
    ):
        """Fetch evidence and execute the authoritative correlation engine."""
        started = perf_counter()

        evidence = self._fetch_evidence(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )
        fetched_at = perf_counter()

        result = self.engine.process(evidence, context=context)

        completed_at = perf_counter()

        print(
            "Correlation timing: "
            f"fetch={(fetched_at - started) * 1000:.1f} ms, "
            f"engine={(completed_at - fetched_at) * 1000:.1f} ms, "
            f"total={(completed_at - started) * 1000:.1f} ms, "
            f"evidence={len(evidence)}, "
            f"candidates={result.candidate_count}, "
            f"findings={result.finding_count}"
        )

        return result

    # def correlate(
    #     self,
    #     *,
    #     tenant_id: str | None = None,
    #     instance_name: str | None = None,
    #     limit: int | None = None,
    # ):
    #     """
    #     Fetch authoritative evidence and pass it to the
    #     authoritative CorrelationEngine.
    #     """
    #     started = perf_counter()

    #     evidence = self._fetch_evidence(
    #         tenant_id=tenant_id,
    #         instance_name=instance_name,
    #         limit=limit,
    #     )
    #     fetched_at = perf_counter()

    #     result = self.engine.process(evidence)

    #     completed_at = perf_counter()

    #     print(
    #         "Correlation timing: "
    #         f"fetch={(fetched_at - started) * 1000:.1f} ms, "
    #         f"engine={(completed_at - fetched_at) * 1000:.1f} ms, "
    #         f"total={(completed_at - started) * 1000:.1f} ms, "
    #         f"evidence={len(evidence)}, "
    #         f"candidates={result.candidate_count}, "
    #         f"findings={result.finding_count}"
    #     )

    #     return result

    

        # return self.engine.process(evidence)

    def findings(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ):
        """
        Return only findings from the complete correlation result.
        """

        result = self.correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )

        return result.findings

    def presentation(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Return a dashboard representation of the authoritative result.

        Correlation still executes through the existing service and engine.
        The adapter only shapes the returned result for presentation.
        """
        result = self.correlate(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )
        return self.presentation_adapter.adapt(result)

    