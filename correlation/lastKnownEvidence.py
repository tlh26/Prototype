# correlation/lastKnownEvidence.py

from __future__ import annotations

import base64
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


class LastKnownEvidenceStore:
    """
    Persistent local read-side cache for Central evidence.

    PostgreSQL remains the authoritative source.

    This store exists only so the dashboard can continue displaying the
    most recently retrieved evidence when Central PostgreSQL is unavailable.

    Cached data must always be presented to the user as stale / last-known
    data and must never be represented as live Central data.
    """

    def __init__(
        self,
        path: str | Path | None = None,
    ) -> None:
        configured_path = (
            path
            or os.getenv(
                "DASHBOARD_LAST_KNOWN_DB",
                "storage/dashboard_last_known.db",
            )
        )

        self.path = Path(configured_path)

        if self.path != Path(":memory:"):
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._initialise()

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")

        return connection

    def _initialise(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS records (
                    evidence_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                );
                """
            )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now().astimezone().isoformat()

    def _set_metadata(
        self,
        connection: sqlite3.Connection,
        key: str,
        value: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO metadata(key, value)
            VALUES (?, ?)
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _get_metadata(
        self,
        connection: sqlite3.Connection,
        key: str,
    ) -> str | None:
        row = connection.execute(
            """
            SELECT value
            FROM metadata
            WHERE key = ?
            """,
            (key,),
        ).fetchone()

        if row is None:
            return None

        return row["value"]

    @property
    def last_successful_read(self) -> datetime | None:
        with self._connect() as connection:
            value = self._get_metadata(
                connection,
                "last_successful_read",
            )

        if not value:
            return None

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def save_events(
        self,
        events: tuple[Any, ...],
    ) -> None:
        if not events:
            return

        cached_at = self._now()

        with self._connect() as connection:
            for event in events:
                payload = self._event_to_payload(event)

                connection.execute(
                    """
                    INSERT INTO events(
                        event_id,
                        payload,
                        cached_at
                    )
                    VALUES (?, ?, ?)
                    ON CONFLICT(event_id)
                    DO UPDATE SET
                        payload = excluded.payload,
                        cached_at = excluded.cached_at
                    """,
                    (
                        str(event.event_id),
                        json.dumps(
                            payload,
                            separators=(",", ":"),
                        ),
                        cached_at,
                    ),
                )

            self._set_metadata(
                connection,
                "last_successful_read",
                cached_at,
            )

    def get_events(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        if limit <= 0:
            return ()

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM events
                ORDER BY json_extract(payload, '$.timestamp') ASC,
                         event_id ASC
                """
            ).fetchall()

        results: list[dict[str, Any]] = []

        for row in rows:
            payload = json.loads(row["payload"])

            if (
                tenant_id is not None
                and payload.get("tenant_id") != tenant_id
            ):
                continue

            if (
                instance_name is not None
                and payload.get("instance_name") != instance_name
            ):
                continue

            results.append(payload)

            if len(results) >= limit:
                break

        return tuple(results)

    def get_event(
        self,
        event_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

        if row is None:
            return None

        return json.loads(row["payload"])

    # ------------------------------------------------------------------
    # Records
    # ------------------------------------------------------------------

    def save_records(
        self,
        records: tuple[Any, ...],
    ) -> None:
        if not records:
            return

        cached_at = self._now()

        with self._connect() as connection:
            for record in records:
                payload = self._record_to_payload(record)

                connection.execute(
                    """
                    INSERT INTO records(
                        evidence_id,
                        payload,
                        cached_at
                    )
                    VALUES (?, ?, ?)
                    ON CONFLICT(evidence_id)
                    DO UPDATE SET
                        payload = excluded.payload,
                        cached_at = excluded.cached_at
                    """,
                    (
                        str(record.evidence_id),
                        json.dumps(
                            payload,
                            separators=(",", ":"),
                        ),
                        cached_at,
                    ),
                )

            self._set_metadata(
                connection,
                "last_successful_read",
                cached_at,
            )

    def get_records(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        if limit <= 0:
            return ()

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM records
                ORDER BY json_extract(payload, '$.collected_at') ASC,
                         evidence_id ASC
                """
            ).fetchall()

        results: list[dict[str, Any]] = []

        for row in rows:
            payload = json.loads(row["payload"])

            if (
                tenant_id is not None
                and payload.get("tenant_id") != tenant_id
            ):
                continue

            if (
                instance_name is not None
                and payload.get("instance_name") != instance_name
            ):
                continue

            results.append(payload)

            if len(results) >= limit:
                break

        return tuple(results)

    def get_record(
        self,
        evidence_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM records
                WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()

        if row is None:
            return None

        return json.loads(row["payload"])

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    def get_tenants(self) -> tuple[str, ...]:
        tenants: set[str] = set()

        with self._connect() as connection:
            event_rows = connection.execute(
                """
                SELECT DISTINCT json_extract(payload, '$.tenant_id') AS tenant_id
                FROM events
                WHERE json_extract(payload, '$.tenant_id') IS NOT NULL
                """
            ).fetchall()

            record_rows = connection.execute(
                """
                SELECT DISTINCT json_extract(payload, '$.tenant_id') AS tenant_id
                FROM records
                WHERE json_extract(payload, '$.tenant_id') IS NOT NULL
                """
            ).fetchall()

        for row in (*event_rows, *record_rows):
            if row["tenant_id"]:
                tenants.add(row["tenant_id"])

        return tuple(sorted(tenants))

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _datetime_to_string(value: Any) -> str | None:
        if value is None:
            return None

        if isinstance(value, datetime):
            return value.isoformat()

        return str(value)

    @staticmethod
    def _bytes_to_base64(value: Any) -> str | None:
        if value is None:
            return None

        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")

        if isinstance(value, memoryview):
            return base64.b64encode(value.tobytes()).decode("ascii")

        if isinstance(value, str):
            return value

        raise TypeError(
            f"Unsupported raw_data type: {type(value)!r}"
        )

    @classmethod
    def _event_to_payload(
        cls,
        event: Any,
    ) -> dict[str, Any]:
        evidence_type = getattr(
            event.evidence_type,
            "value",
            event.evidence_type,
        )

        event_type = getattr(
            event.event_type,
            "value",
            event.event_type,
        )

        return {
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "instance_name": event.instance_name,
            "evidence_type": evidence_type,
            "event_type": event_type,
            "timestamp": cls._datetime_to_string(
                event.timestamp
            ),
            "created_at": cls._datetime_to_string(
                event.created_at
            ),
            "actor": event.actor,
            "uid": event.uid,
            "resource": event.resource,
            "source": event.source,
            "source_path": event.source_path,
            "details": event.details,
            "sequence": event.sequence,
            "agent_id": event.agent_id,
            "raw_data": cls._bytes_to_base64(
                event.raw_data
            ),
            "sha256": event.sha256,
        }

    @classmethod
    def _record_to_payload(
        cls,
        record: Any,
    ) -> dict[str, Any]:
        return {
            "evidence_id": record.evidence_id,
            "tenant_id": record.tenant_id,
            "tenant_hash": record.tenant_hash,
            "project_id": record.project_id,
            "instance_name": record.instance_name,
            "scope": record.scope,
            "source": record.source,
            "source_path": record.source_path,
            "acquisition_layer": record.acquisition_layer,
            "acquired_from": record.acquired_from,
            "attribution_method": record.attribution_method,
            "collected_at": cls._datetime_to_string(
                record.collected_at
            ),
            "raw_data": cls._bytes_to_base64(
                record.raw_data
            ),
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "sequence_start": record.sequence_start,
            "sequence_end": record.sequence_end,
            "capture_id": record.capture_id,
            "record_sha256": record.record_sha256,
        }

    # ------------------------------------------------------------------
    # Cache inspection
    # ------------------------------------------------------------------

    def has_data(self) -> bool:
        with self._connect() as connection:
            event_exists = connection.execute(
                """
                SELECT 1
                FROM events
                LIMIT 1
                """
            ).fetchone()

            if event_exists is not None:
                return True

            record_exists = connection.execute(
                """
                SELECT 1
                FROM records
                LIMIT 1
                """
            ).fetchone()

            return record_exists is not None