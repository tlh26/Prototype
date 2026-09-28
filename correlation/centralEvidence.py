# correlation/centralEvidence.py

from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import psycopg

from central.config import CentralConfig
from central.database import get_connection
from correlation.lastKnownEvidence import LastKnownEvidenceStore


class CentralEvidenceUnavailable(Exception):
    """Raised when the central evidence store cannot be reached."""


class PostgreSQLCorrelationSource:
    """
    Read authoritative evidence from the Central PostgreSQL database.

    PostgreSQL remains the authoritative source.

    When PostgreSQL is unavailable, previously retrieved evidence may be
    served from the local last-known evidence store. Callers can inspect
    ``using_last_known_data`` to distinguish live data from stale data.

    The local store is a read-side resilience mechanism only. It never
    writes to Central PostgreSQL and never changes authoritative evidence.
    """

    def __init__(
        self,
        config: CentralConfig | None = None,
        last_known_store: LastKnownEvidenceStore | None = None,
    ) -> None:
        self.config = config or CentralConfig()

        self.last_known_store = (
            last_known_store
            if last_known_store is not None
            else LastKnownEvidenceStore()
        )

        self._using_last_known_data = False
        self._central_available = True

    # ------------------------------------------------------------------
    # Request state
    # ------------------------------------------------------------------

    def begin_read(self) -> None:
        """
        Reset request-level availability state.

        Views should call this once before invoking a service that may
        perform multiple source reads.
        """
        self._using_last_known_data = False
        self._central_available = True

    @property
    def using_last_known_data(self) -> bool:
        return self._using_last_known_data

    @property
    def central_available(self) -> bool:
        return self._central_available

    @property
    def last_known_timestamp(self) -> datetime | None:
        return self.last_known_store.last_successful_read

    # ------------------------------------------------------------------
    # Central connection handling
    # ------------------------------------------------------------------

    @staticmethod
    def _is_connection_error(exc: Exception) -> bool:
        return isinstance(
            exc,
            (
                psycopg.OperationalError,
                psycopg.InterfaceError,
            ),
        )

    def _mark_live(self) -> None:
        self._central_available = True

    def _mark_cached(self) -> None:
        self._central_available = False
        self._using_last_known_data = True

    def _mark_unavailable(self) -> None:
        self._central_available = False

    # ------------------------------------------------------------------
    # Instance evidence
    # ------------------------------------------------------------------

    def fetch_events(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int = 100,
    ) -> tuple[Any, ...]:

        if limit <= 0:
            return ()

        query = """
            SELECT
                event_id,
                tenant_id,
                instance_name,
                evidence_type,
                event_type,
                timestamp,
                actor,
                uid,
                resource,
                source,
                source_path,
                details_json,
                sequence,
                agent_id,
                raw_data,
                sha256,
                created_at
            FROM evidence_events
            WHERE 1 = 1
        """

        parameters: list[Any] = []

        if tenant_id is not None:
            query += """
                AND tenant_id = %s
            """
            parameters.append(tenant_id)

        if instance_name is not None:
            query += """
                AND instance_name = %s
            """
            parameters.append(instance_name)

        query += """
            ORDER BY timestamp ASC, event_id ASC
            LIMIT %s
        """

        parameters.append(limit)

        try:
            with get_connection(self.config) as connection:
                rows = connection.execute(
                    query,
                    parameters,
                ).fetchall()

        except Exception as exc:
            if not self._is_connection_error(exc):
                raise

            cached = self.last_known_store.get_events(
                tenant_id=tenant_id,
                instance_name=instance_name,
                limit=limit,
            )

            if not cached:
                self._mark_unavailable()

                raise CentralEvidenceUnavailable(
                    "The central evidence store is currently unavailable "
                    "and no cached evidence is available."
                ) from exc

            self._mark_cached()

            return tuple(
                self._event_from_cache_payload(payload)
                for payload in cached
            )

        events = tuple(
            self._event_from_row(row)
            for row in rows
        )

        self.last_known_store.save_events(events)

        self._mark_live()

        return events

    def fetch_event(
        self,
        event_id: str,
    ) -> Any | None:

        try:
            with get_connection(self.config) as connection:
                row = connection.execute(
                    """
                    SELECT
                        event_id,
                        tenant_id,
                        instance_name,
                        evidence_type,
                        event_type,
                        timestamp,
                        actor,
                        uid,
                        resource,
                        source,
                        source_path,
                        details_json,
                        sequence,
                        agent_id,
                        raw_data,
                        sha256,
                        created_at
                    FROM evidence_events
                    WHERE event_id = %s
                    """,
                    (event_id,),
                ).fetchone()

        except Exception as exc:
            if not self._is_connection_error(exc):
                raise

            cached = self.last_known_store.get_event(
                event_id,
            )

            if cached is None:
                self._mark_unavailable()

                raise CentralEvidenceUnavailable(
                    "The central evidence store is currently unavailable "
                    "and the requested evidence is not present in the "
                    "last-known cache."
                ) from exc

            self._mark_cached()

            return self._event_from_cache_payload(
                cached,
            )

        self._mark_live()

        if row is None:
            return None

        event = self._event_from_row(row)

        self.last_known_store.save_events(
            (event,),
        )

        return event

    # ------------------------------------------------------------------
    # Host evidence
    # ------------------------------------------------------------------

    def fetch_records(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int = 100,
    ) -> tuple[Any, ...]:

        if limit <= 0:
            return ()

        query = """
            SELECT
                evidence_id,
                tenant_id,
                tenant_hash,
                project_id,
                instance_name,
                scope,
                source,
                source_path,
                acquisition_layer,
                acquired_from,
                attribution_method,
                collected_at,
                raw_data,
                sha256,
                size_bytes,
                sequence_start,
                sequence_end,
                capture_id,
                record_sha256
            FROM evidence_records
            WHERE 1 = 1
        """

        parameters: list[Any] = []

        if tenant_id is not None:
            query += """
                AND tenant_id = %s
            """
            parameters.append(tenant_id)

        if instance_name is not None:
            query += """
                AND instance_name = %s
            """
            parameters.append(instance_name)

        query += """
            ORDER BY collected_at ASC, evidence_id ASC
            LIMIT %s
        """

        parameters.append(limit)

        try:
            with get_connection(self.config) as connection:
                rows = connection.execute(
                    query,
                    parameters,
                ).fetchall()

        except Exception as exc:
            if not self._is_connection_error(exc):
                raise

            cached = self.last_known_store.get_records(
                tenant_id=tenant_id,
                instance_name=instance_name,
                limit=limit,
            )

            if not cached:
                self._mark_unavailable()

                raise CentralEvidenceUnavailable(
                    "The central evidence store is currently unavailable "
                    "and no cached evidence records are available."
                ) from exc

            self._mark_cached()

            return tuple(
                self._record_from_cache_payload(payload)
                for payload in cached
            )

        records = tuple(
            self._record_from_row(row)
            for row in rows
        )

        self.last_known_store.save_records(records)

        self._mark_live()

        return records

    def fetch_record(
        self,
        evidence_id: str,
    ) -> Any | None:

        try:
            with get_connection(self.config) as connection:
                row = connection.execute(
                    """
                    SELECT
                        evidence_id,
                        tenant_id,
                        tenant_hash,
                        project_id,
                        instance_name,
                        scope,
                        source,
                        source_path,
                        acquisition_layer,
                        acquired_from,
                        attribution_method,
                        collected_at,
                        raw_data,
                        sha256,
                        size_bytes,
                        sequence_start,
                        sequence_end,
                        capture_id,
                        record_sha256
                    FROM evidence_records
                    WHERE evidence_id = %s
                    """,
                    (evidence_id,),
                ).fetchone()

        except Exception as exc:
            if not self._is_connection_error(exc):
                raise

            cached = self.last_known_store.get_record(
                evidence_id,
            )

            if cached is None:
                self._mark_unavailable()

                raise CentralEvidenceUnavailable(
                    "The central evidence store is currently unavailable "
                    "and the requested evidence record is not present in "
                    "the last-known cache."
                ) from exc

            self._mark_cached()

            return self._record_from_cache_payload(
                cached,
            )

        self._mark_live()

        if row is None:
            return None

        record = self._record_from_row(row)

        self.last_known_store.save_records(
            (record,),
        )

        return record

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    def fetch_tenants(self) -> tuple[str, ...]:
        query = """
            SELECT DISTINCT tenant_id
            FROM (
                SELECT tenant_id
                FROM evidence_events

                UNION

                SELECT tenant_id
                FROM evidence_records
            ) AS tenants
            WHERE tenant_id IS NOT NULL
            ORDER BY tenant_id
        """

        try:
            with get_connection(self.config) as connection:
                rows = connection.execute(
                    query,
                ).fetchall()

        except Exception as exc:
            if not self._is_connection_error(exc):
                raise

            cached = self.last_known_store.get_tenants()

            if not cached:
                self._mark_unavailable()

                raise CentralEvidenceUnavailable(
                    "The central evidence store is currently unavailable "
                    "and no cached tenant information is available."
                ) from exc

            self._mark_cached()

            return cached

        self._mark_live()

        return tuple(
            row["tenant_id"]
            for row in rows
        )

    # ------------------------------------------------------------------
    # Row adapters
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value

        return datetime.fromisoformat(
            str(value).replace(
                "Z",
                "+00:00",
            )
        )

    @staticmethod
    def _decode_raw_data(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value

        if isinstance(value, memoryview):
            return value.tobytes()

        if isinstance(value, str):
            return base64.b64decode(value)

        raise TypeError(
            f"Unsupported raw_data type: {type(value)!r}"
        )

    @classmethod
    def _event_from_row(
        cls,
        row: dict[str, Any],
    ) -> Any:

        details = row["details_json"]

        if isinstance(details, str):
            details = json.loads(details)

        return SimpleNamespace(
            event_id=row["event_id"],
            tenant_id=row["tenant_id"],
            instance_name=row["instance_name"],
            evidence_type=SimpleNamespace(
                value=row["evidence_type"],
            ),
            event_type=SimpleNamespace(
                value=row["event_type"],
            ),
            timestamp=cls._parse_datetime(
                row["timestamp"],
            ),
            created_at=cls._parse_datetime(
                row["created_at"],
            ),
            actor=row["actor"],
            uid=row["uid"],
            resource=row["resource"],
            source=row["source"],
            source_path=row["source_path"],
            details=details,
            sequence=row["sequence"],
            agent_id=row["agent_id"],
            raw_data=cls._decode_raw_data(
                row["raw_data"],
            ),
            sha256=row["sha256"],
        )

    @classmethod
    def _record_from_row(
        cls,
        row: dict[str, Any],
    ) -> Any:

        return SimpleNamespace(
            evidence_id=row["evidence_id"],
            tenant_id=row["tenant_id"],
            tenant_hash=row["tenant_hash"],
            project_id=row["project_id"],
            instance_name=row["instance_name"],
            scope=row["scope"],
            source=row["source"],
            source_path=row["source_path"],
            acquisition_layer=row["acquisition_layer"],
            acquired_from=row["acquired_from"],
            attribution_method=row["attribution_method"],
            collected_at=cls._parse_datetime(
                row["collected_at"],
            ),
            raw_data=cls._decode_raw_data(
                row["raw_data"],
            ),
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            sequence_start=row["sequence_start"],
            sequence_end=row["sequence_end"],
            capture_id=row["capture_id"],
            record_sha256=row["record_sha256"],
        )

    # ------------------------------------------------------------------
    # Cache adapters
    # ------------------------------------------------------------------

    @classmethod
    def _event_from_cache_payload(
        cls,
        payload: dict[str, Any],
    ) -> Any:

        return SimpleNamespace(
            event_id=payload["event_id"],
            tenant_id=payload["tenant_id"],
            instance_name=payload["instance_name"],
            evidence_type=SimpleNamespace(
                value=payload["evidence_type"],
            ),
            event_type=SimpleNamespace(
                value=payload["event_type"],
            ),
            timestamp=cls._parse_datetime(
                payload["timestamp"],
            ),
            created_at=cls._parse_datetime(
                payload["created_at"],
            ),
            actor=payload["actor"],
            uid=payload["uid"],
            resource=payload["resource"],
            source=payload["source"],
            source_path=payload["source_path"],
            details=payload["details"],
            sequence=payload["sequence"],
            agent_id=payload["agent_id"],
            raw_data=cls._decode_raw_data(
                payload["raw_data"],
            ),
            sha256=payload["sha256"],
        )

    @classmethod
    def _record_from_cache_payload(
        cls,
        payload: dict[str, Any],
    ) -> Any:

        return SimpleNamespace(
            evidence_id=payload["evidence_id"],
            tenant_id=payload["tenant_id"],
            tenant_hash=payload["tenant_hash"],
            project_id=payload["project_id"],
            instance_name=payload["instance_name"],
            scope=payload["scope"],
            source=payload["source"],
            source_path=payload["source_path"],
            acquisition_layer=payload["acquisition_layer"],
            acquired_from=payload["acquired_from"],
            attribution_method=payload["attribution_method"],
            collected_at=cls._parse_datetime(
                payload["collected_at"],
            ),
            raw_data=cls._decode_raw_data(
                payload["raw_data"],
            ),
            sha256=payload["sha256"],
            size_bytes=payload["size_bytes"],
            sequence_start=payload["sequence_start"],
            sequence_end=payload["sequence_end"],
            capture_id=payload["capture_id"],
            record_sha256=payload["record_sha256"],
        )


# Backwards-compatible name while the codebase transitions.
CentralEvidenceReader = PostgreSQLCorrelationSource