from __future__ import annotations

from typing import Any

from correlation.centralEvidence import PostgreSQLCorrelationSource
from correlation.engine import CorrelationEngine


class CorrelationService:
    """
    Presentation-facing service for running the authoritative
    correlation engine against evidence stored in Central PostgreSQL.

    This service deliberately contains no correlation algorithms.
    CorrelationEngine remains the single authoritative location for
    normalization, entity extraction, relationship mapping, and rules.
    """

    def __init__(
        self,
        *,
        source: PostgreSQLCorrelationSource,
        engine: CorrelationEngine,
        evidence_limit: int = 100,
    ) -> None:
        self.source = source
        self.engine = engine
        self.evidence_limit = evidence_limit

    def correlate(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int | None = None,
    ):
        """
        Fetch authoritative evidence and pass it unchanged to the
        authoritative CorrelationEngine.

        Both instance events and host evidence records are included.
        """

        effective_limit = (
            self.evidence_limit
            if limit is None
            else limit
        )

        if effective_limit <= 0:
            return self.engine.process(())

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

        # Keep the source-specific evidence together for the engine.
        evidence: tuple[Any, ...] = events + records

        return self.engine.process(evidence)

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