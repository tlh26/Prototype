# correlation/centralEvidence.py

from __future__ import annotations

import base64
import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from central.config import CentralConfig
from central.database import get_connection


class PostgreSQLCorrelationSource:
    """
    Read authoritative evidence from the Central PostgreSQL database.

    This source is read-only. It adapts PostgreSQL rows from
    evidence_events and evidence_records into objects consumed by
    EvidenceNormaliser.

    It does not modify Central evidence and does not persist
    correlation results.
    """

    def __init__(
        self,
        config: CentralConfig | None = None,
    ) -> None:
        self.config = config or CentralConfig()

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

        with get_connection(self.config) as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return tuple(self._event_from_row(row) for row in rows)

    def fetch_event(
        self,
        event_id: str,
    ) -> Any | None:

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

        if row is None:
            return None

        return self._event_from_row(row)

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

        with get_connection(self.config) as connection:
            rows = connection.execute(
                query,
                parameters,
            ).fetchall()

        return tuple(self._record_from_row(row) for row in rows)

    def fetch_record(
        self,
        evidence_id: str,
    ) -> Any | None:

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

        if row is None:
            return None

        return self._record_from_row(row)

    # ------------------------------------------------------------------
    # Row adapters
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_datetime(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value

        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    @staticmethod
    def _decode_raw_data(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value

        if isinstance(value, memoryview):
            return value.tobytes()

        if isinstance(value, str):
            return base64.b64decode(value)

        raise TypeError(f"Unsupported raw_data type: {type(value)!r}")

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


# Backwards-compatible name while the codebase transitions.
CentralEvidenceReader = PostgreSQLCorrelationSource
