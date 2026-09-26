from __future__ import annotations

from typing import Any

from correlation.centralEvidence import PostgreSQLCorrelationSource


class EvidenceService:
    """
    Presentation-facing service for browsing authoritative evidence
    stored in Central PostgreSQL.

    This service contains no SQL and does not modify evidence.
    All database access is delegated to PostgreSQLCorrelationSource.
    """

    def __init__(
        self,
        *,
        source: PostgreSQLCorrelationSource,
        evidence_limit: int = 100,
    ) -> None:
        self.source = source
        self.evidence_limit = evidence_limit

    def list_evidence(
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

    def get_evidence(self, evidence_id: str) -> Any | None:
        """
        Retrieve one evidence item by its authoritative evidence ID.

        Evidence events and forensic records use different source
        tables, so both lookup methods are attempted.
        """

        event = self.source.fetch_event(evidence_id)

        if event is not None:
            return event

        return self.source.fetch_record(evidence_id)