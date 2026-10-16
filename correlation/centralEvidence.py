
# correlation/centralEvidence.py

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime
from time import perf_counter
from types import SimpleNamespace
from typing import Any

import psycopg

from central.config import CentralConfig
from central.database import get_connection
from correlation.lastKnownEvidence import LastKnownEvidenceStore
from evidenceAgent.evidenceAgent.models import EvidenceEvent


logger = logging.getLogger(__name__)


def log_timing(
    operation: str,
    started: float,
    **fields: Any,
) -> None:
    """Log elapsed time and non-sensitive diagnostic fields."""
    elapsed_ms = (perf_counter() - started) * 1000

    details = " ".join(
        f"{key}={value}"
        for key, value in fields.items()
    )

    logger.info(
        "%s elapsed_ms=%.1f%s",
        operation,
        elapsed_ms,
        f" {details}" if details else "",
    )


class CentralEvidenceUnavailable(Exception):
    """Raised when PostgreSQL is unavailable and no suitable cache exists."""


class PostgreSQLCorrelationSource:
    """
    Read authoritative evidence from Central PostgreSQL.

    The local last-known store is a read fallback only. Cached evidence is
    not written back to PostgreSQL and must be treated as potentially stale.

    Timing logs distinguish connection setup, SQL execution, conversion,
    cache persistence, and fallback-cache reads.

    Availability state is maintained for a logical dashboard request.
    Call begin_read() once at the start of that request.
    """

    EVENT_SELECT = """
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
    """

    RECORD_SELECT = """
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
        Reset availability indicators before a logical request.

        Do not call this between evidence reads belonging to the same
        dashboard request.
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

    @staticmethod
    def _is_connection_error(exc: Exception) -> bool:
        """
        Identify connection-level errors eligible for cache fallback.

        Query, schema, conversion, and other programming errors should
        propagate instead of being hidden as ordinary database outages.
        """
        return isinstance(
            exc,
            (
                psycopg.OperationalError,
                psycopg.InterfaceError,
            ),
        )

    def _mark_live(self) -> None:
        """
        Record a successful live PostgreSQL operation.

        Do not clear _using_last_known_data here: another operation during
        the same request may already have used cached evidence.
        """
        self._central_available = True

    def _mark_cached(self) -> None:
        """Record that a read is being served from the local cache."""
        self._central_available = False
        self._using_last_known_data = True

    def _mark_unavailable(self) -> None:
        """Record that a required read could not be satisfied."""
        self._central_available = False

    # ------------------------------------------------------------------
    # Connection and query helpers
    # ------------------------------------------------------------------

    def _execute_fetchall(
        self,
        operation: str,
        query: str,
        parameters: tuple[Any, ...] | list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a query and measure connection and query latency."""
        started = perf_counter()

        try:
            connection = get_connection(self.config)
        except Exception:
            log_timing(
                f"{operation}.connect_failed",
                started,
            )
            raise

        log_timing(
            f"{operation}.connect",
            started,
        )

        with connection:
            query_started = perf_counter()

            if parameters is None:
                rows = connection.execute(query).fetchall()
            else:
                rows = connection.execute(
                    query,
                    parameters,
                ).fetchall()

            log_timing(
                f"{operation}.query",
                query_started,
                rows=len(rows),
            )

        return rows

    def _execute_fetchone(
        self,
        operation: str,
        query: str,
        parameters: tuple[Any, ...] | list[Any] | None = None,
    ) -> dict[str, Any] | None:
        """Execute a single-row query with connection/query timings."""
        started = perf_counter()

        try:
            connection = get_connection(self.config)
        except Exception:
            log_timing(
                f"{operation}.connect_failed",
                started,
            )
            raise

        log_timing(
            f"{operation}.connect",
            started,
        )

        with connection:
            query_started = perf_counter()

            if parameters is None:
                row = connection.execute(query).fetchone()
            else:
                row = connection.execute(
                    query,
                    parameters,
                ).fetchone()

            log_timing(
                f"{operation}.query",
                query_started,
                found=row is not None,
            )

        return row

    # ------------------------------------------------------------------
    # Cache persistence
    # ------------------------------------------------------------------

    def _save_events_to_cache(
        self,
        events: tuple[Any, ...],
    ) -> None:
        """Persist live events without making cache failure fatal."""
        if not events:
            return

        started = perf_counter()

        try:
            self.last_known_store.save_events(events)
        except Exception:
            logger.exception(
                "evidence.cache_save_failed type=events count=%d",
                len(events),
            )
        finally:
            log_timing(
                "evidence.cache_save",
                started,
                type="events",
                count=len(events),
            )

    def _save_records_to_cache(
        self,
        records: tuple[Any, ...],
    ) -> None:
        """Persist live evidence records without making cache failure fatal."""
        if not records:
            return

        started = perf_counter()

        try:
            self.last_known_store.save_records(records)
        except Exception:
            logger.exception(
                "evidence.cache_save_failed type=records count=%d",
                len(records),
            )
        finally:
            log_timing(
                "evidence.cache_save",
                started,
                type="records",
                count=len(records),
            )

    # ------------------------------------------------------------------
    # Cache reads and adapters
    # ------------------------------------------------------------------

    def _cached_events(
        self,
        *,
        tenant_id: str | None,
        instance_name: str | None,
        limit: int,
    ) -> tuple[Any, ...]:
        started = perf_counter()

        cached = self.last_known_store.get_events(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )

        log_timing(
            "evidence.cache_read",
            started,
            type="events",
            count=len(cached),
        )

        conversion_started = perf_counter()
        events = tuple(
            self._event_from_cache_payload(payload)
            for payload in cached
        )

        log_timing(
            "evidence.cache_convert",
            conversion_started,
            type="events",
            count=len(events),
        )

        return events

    def _cached_records(
        self,
        *,
        tenant_id: str | None,
        instance_name: str | None,
        limit: int,
    ) -> tuple[Any, ...]:
        started = perf_counter()

        cached = self.last_known_store.get_records(
            tenant_id=tenant_id,
            instance_name=instance_name,
            limit=limit,
        )

        log_timing(
            "evidence.cache_read",
            started,
            type="records",
            count=len(cached),
        )

        conversion_started = perf_counter()
        records = tuple(
            self._record_from_cache_payload(payload)
            for payload in cached
        )

        log_timing(
            "evidence.cache_convert",
            conversion_started,
            type="records",
            count=len(records),
        )

        return records

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

        query = self.EVENT_SELECT + "\nWHERE 1 = 1"
        parameters: list[Any] = []

        if tenant_id is not None:
            query += "\nAND tenant_id = %s"
            parameters.append(tenant_id)

        if instance_name is not None:
            query += "\nAND instance_name = %s"
            parameters.append(instance_name)

        query += "\nORDER BY timestamp DESC, event_id DESC"
        query += "\nLIMIT %s"
        parameters.append(limit)

        started = perf_counter()

        try:
            rows = self._execute_fetchall(
                "evidence.fetch_events",
                query,
                parameters,
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_read_failed",
                started,
                read_type="events",
                error_type=type(exc).__name__,
            )

            if not self._is_connection_error(exc):
                raise

            logger.warning(
                "evidence.central_read_failed type=events error_type=%s",
                type(exc).__name__,
            )

            cached = self._cached_events(
                tenant_id=tenant_id,
                instance_name=instance_name,
                limit=limit,
            )

            if not cached:
                self._mark_unavailable()
                raise CentralEvidenceUnavailable(
                    "The central evidence store is unavailable and "
                    "no matching cached events are available."
                ) from exc

            self._mark_cached()
            return cached

        conversion_started = perf_counter()
        events = tuple(
            self._event_from_row(row)
            for row in reversed(rows)
        )

        log_timing(
            "evidence.fetch_events.convert",
            conversion_started,
            count=len(events),
        )

        self._mark_live()
        self._save_events_to_cache(events)

        return events

    def fetch_event(
        self,
        event_id: str,
    ) -> Any | None:
        query = self.EVENT_SELECT + "\nWHERE event_id = %s"
        started = perf_counter()

        try:
            row = self._execute_fetchone(
                "evidence.fetch_event",
                query,
                (event_id,),
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_read_failed",
                started,
                read_type="event",
                error_type=type(exc).__name__,
            )

            if not self._is_connection_error(exc):
                raise

            logger.warning(
                "evidence.central_read_failed type=event error_type=%s",
                type(exc).__name__,
            )

            cache_started = perf_counter()
            cached = self.last_known_store.get_event(event_id)

            log_timing(
                "evidence.cache_read",
                cache_started,
                type="event",
                found=cached is not None,
            )

            if cached is None:
                self._mark_unavailable()
                raise CentralEvidenceUnavailable(
                    "The central evidence store is unavailable and "
                    "the requested event is not in the last-known cache."
                ) from exc

            self._mark_cached()
            return self._event_from_cache_payload(cached)

        self._mark_live()

        if row is None:
            return None

        conversion_started = perf_counter()
        event = self._event_from_row(row)

        log_timing(
            "evidence.fetch_event.convert",
            conversion_started,
            count=1,
        )

        self._save_events_to_cache((event,))
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

        query = self.RECORD_SELECT + "\nWHERE 1 = 1"
        parameters: list[Any] = []

        if tenant_id is not None:
            query += "\nAND tenant_id = %s"
            parameters.append(tenant_id)

        if instance_name is not None:
            query += "\nAND instance_name = %s"
            parameters.append(instance_name)

        query += "\nORDER BY collected_at DESC, evidence_id DESC"
        query += "\nLIMIT %s"
        parameters.append(limit)

        started = perf_counter()

        try:
            rows = self._execute_fetchall(
                "evidence.fetch_records",
                query,
                parameters,
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_read_failed",
                started,
                read_type="records",
                error_type=type(exc).__name__,
            )

            if not self._is_connection_error(exc):
                raise

            logger.warning(
                "evidence.central_read_failed type=records error_type=%s",
                type(exc).__name__,
            )

            cached = self._cached_records(
                tenant_id=tenant_id,
                instance_name=instance_name,
                limit=limit,
            )

            if not cached:
                self._mark_unavailable()
                raise CentralEvidenceUnavailable(
                    "The central evidence store is unavailable and "
                    "no matching cached evidence records are available."
                ) from exc

            self._mark_cached()
            return cached

        conversion_started = perf_counter()
        records = tuple(
            self._record_from_row(row)
            for row in reversed(rows)
        )

        log_timing(
            "evidence.fetch_records.convert",
            conversion_started,
            count=len(records),
        )

        self._mark_live()
        self._save_records_to_cache(records)

        return records

    def fetch_record(
        self,
        evidence_id: str,
    ) -> Any | None:
        query = self.RECORD_SELECT + "\nWHERE evidence_id = %s"
        started = perf_counter()

        try:
            row = self._execute_fetchone(
                "evidence.fetch_record",
                query,
                (evidence_id,),
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_read_failed",
                started,
                read_type="record",
                error_type=type(exc).__name__,
            )

            if not self._is_connection_error(exc):
                raise

            logger.warning(
                "evidence.central_read_failed type=record error_type=%s",
                type(exc).__name__,
            )

            cache_started = perf_counter()
            cached = self.last_known_store.get_record(evidence_id)

            log_timing(
                "evidence.cache_read",
                cache_started,
                type="record",
                found=cached is not None,
            )

            if cached is None:
                self._mark_unavailable()
                raise CentralEvidenceUnavailable(
                    "The central evidence store is unavailable and "
                    "the requested evidence record is not in the cache."
                ) from exc

            self._mark_cached()
            return self._record_from_cache_payload(cached)

        self._mark_live()

        if row is None:
            return None

        conversion_started = perf_counter()
        record = self._record_from_row(row)

        log_timing(
            "evidence.fetch_record.convert",
            conversion_started,
            count=1,
        )

        self._save_records_to_cache((record,))
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

        started = perf_counter()

        try:
            rows = self._execute_fetchall(
                "evidence.fetch_tenants",
                query,
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_read_failed",
                started,
                read_type="tenants",
                error_type=type(exc).__name__,
            )

            if not self._is_connection_error(exc):
                raise

            logger.warning(
                "evidence.central_read_failed type=tenants error_type=%s",
                type(exc).__name__,
            )

            cache_started = perf_counter()
            cached = self.last_known_store.get_tenants()

            log_timing(
                "evidence.cache_read",
                cache_started,
                type="tenants",
                count=len(cached),
            )

            if not cached:
                self._mark_unavailable()
                raise CentralEvidenceUnavailable(
                    "The central evidence store is unavailable and "
                    "no cached tenant information is available."
                ) from exc

            self._mark_cached()
            return tuple(cached)

        self._mark_live()

        return tuple(
            row["tenant_id"]
            for row in rows
            if row["tenant_id"] is not None
        )

    # ------------------------------------------------------------------
    # Row adapters
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value

        if value is None:
            raise ValueError("Cannot parse a missing timestamp.")

        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    @staticmethod
    def _decode_raw_data(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value

        if isinstance(value, memoryview):
            return value.tobytes()

        if isinstance(value, str):
            return base64.b64decode(value, validate=True)

        raise TypeError(
            f"Unsupported raw_data type: {type(value)!r}"
        )

    @classmethod
    def _event_from_row(
        cls,
        row: dict[str, Any],
    ) -> EvidenceEvent:
        details = row["details_json"]

        if isinstance(details, str):
            details = json.loads(details)

        return EvidenceEvent(
            event_id=row["event_id"],
            tenant_id=row["tenant_id"],
            instance_name=row["instance_name"],
            evidence_type=row["evidence_type"],
            event_type=row["event_type"],
            timestamp=cls._parse_datetime(row["timestamp"]),
            actor=row["actor"],
            uid=row["uid"],
            resource=row["resource"],
            source=row["source"],
            source_path=row["source_path"],
            details=details,
            sequence=row["sequence"],
            agent_id=row["agent_id"],
            raw_data=cls._decode_raw_data(row["raw_data"]),
            sha256=row["sha256"],
            created_at=cls._parse_datetime(row["created_at"]),
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
            collected_at=cls._parse_datetime(row["collected_at"]),
            raw_data=cls._decode_raw_data(row["raw_data"]),
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
    ) -> EvidenceEvent:
        return EvidenceEvent(
            event_id=payload["event_id"],
            tenant_id=payload["tenant_id"],
            instance_name=payload["instance_name"],
            evidence_type=payload["evidence_type"],
            event_type=payload["event_type"],
            timestamp=cls._parse_datetime(payload["timestamp"]),
            actor=payload["actor"],
            uid=payload["uid"],
            resource=payload["resource"],
            source=payload["source"],
            source_path=payload["source_path"],
            details=payload["details"],
            sequence=payload["sequence"],
            agent_id=payload["agent_id"],
            raw_data=cls._decode_raw_data(payload["raw_data"]),
            sha256=payload["sha256"],
            created_at=cls._parse_datetime(payload["created_at"]),
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
            collected_at=cls._parse_datetime(payload["collected_at"]),
            raw_data=cls._decode_raw_data(payload["raw_data"]),
            sha256=payload["sha256"],
            size_bytes=payload["size_bytes"],
            sequence_start=payload["sequence_start"],
            sequence_end=payload["sequence_end"],
            capture_id=payload["capture_id"],
            record_sha256=payload["record_sha256"],
        )

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def check_central(self) -> bool:
        """Test whether the authoritative PostgreSQL store is reachable."""
        started = perf_counter()

        try:
            self._execute_fetchone(
                "evidence.check_central",
                "SELECT 1",
            )
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            log_timing(
                "evidence.central_health_check_failed",
                started,
                error_type=type(exc).__name__,
            )

            logger.warning(
                "evidence.central_health_check_failed error_type=%s",
                type(exc).__name__,
            )
            self._mark_unavailable()
            return False

        self._mark_live()
        return True


# Backwards-compatible alias.
CentralEvidenceReader = PostgreSQLCorrelationSource
