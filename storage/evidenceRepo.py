# storage/evidenceRepo.py

from __future__ import annotations

import hashlib
import json
import sqlite3

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from acquisition.captureManifest import CaptureManifest
from acquisition.collectors.audit import AuditEvidence
import evidence
from evidence.evidence import EvidenceRecord


class SQLiteEvidenceRepository:
    """
    SQLite-backed repository for central raw evidence storage.

    Responsibilities
    ----------------
    - persist capture manifests;
    - persist immutable raw evidence;
    - preserve evidence provenance;
    - calculate SHA-256 integrity hashes;
    - verify persisted evidence independently;
    - provide transaction boundaries.

    This repository does NOT:
        - collect evidence;
        - parse audit records;
        - resolve tenants;
        - perform correlation.

    Raw evidence is stored directly as a SQLite BLOB.

    Two integrity levels are maintained:

        sha256
            SHA-256 of raw_data.

        record_sha256
            SHA-256 of the canonical evidence metadata plus
            the SHA-256 of raw_data.
    """

    SCHEMA_VERSION = 1

    # ------------------------------------------------------------------
    # INITIALIZATION
    # ------------------------------------------------------------------

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(database_path)

        if str(database_path) != ":memory:":
            self.database_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._initialize_database()

    # ------------------------------------------------------------------
    # CONNECTION
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """
        Create a configured SQLite connection.
        """

        connection = sqlite3.connect(
            self.database_path,
            timeout=30,
        )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")

        connection.execute("PRAGMA journal_mode = WAL")

        connection.execute("PRAGMA synchronous = FULL")

        return connection

    # ------------------------------------------------------------------
    # TRANSACTION
    # ------------------------------------------------------------------

    @contextmanager
    def transaction(
        self,
    ) -> Iterator[sqlite3.Connection]:
        """
        Execute operations inside an explicit transaction.

        The caller owns the transaction boundary.
        """

        connection = self._connect()

        try:
            connection.execute("BEGIN")

            yield connection

            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    # ------------------------------------------------------------------
    # DATABASE INITIALIZATION
    # ------------------------------------------------------------------

    def _initialize_database(self) -> None:
        """
        Create the central evidence schema if it does not exist.
        """

        with self._connect() as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS capture_manifests (
                    capture_id TEXT PRIMARY KEY,

                    status TEXT NOT NULL,

                    started_at TEXT NOT NULL,
                    completed_at TEXT,

                    requested_source_count
                        INTEGER NOT NULL DEFAULT 0,

                    successful_source_count
                        INTEGER NOT NULL DEFAULT 0,

                    failed_source_count
                        INTEGER NOT NULL DEFAULT 0,

                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,

                    capture_id TEXT,

                    tenant_id TEXT,
                    tenant_hash TEXT,

                    project_id TEXT,
                    instance_name TEXT,

                    scope TEXT,

                    source TEXT NOT NULL,
                    source_path TEXT NOT NULL,

                    acquisition_layer TEXT NOT NULL,
                    acquired_from TEXT NOT NULL,
                    attribution_method TEXT NOT NULL,

                    collected_at TEXT NOT NULL,

                    raw_data BLOB NOT NULL,

                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,

                    sequence_start INTEGER,
                    sequence_end INTEGER,

                    record_sha256 TEXT NOT NULL,

                    FOREIGN KEY (capture_id)
                        REFERENCES capture_manifests(capture_id)
                )
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_evidence_tenant
                ON evidence(tenant_id)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_evidence_instance
                ON evidence(instance_name)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_evidence_source
                ON evidence(source)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_evidence_capture
                ON evidence(capture_id)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_evidence_collected_at
                ON evidence(collected_at)
                """)

    # ------------------------------------------------------------------
    # DATETIME
    # ------------------------------------------------------------------

    @staticmethod
    def _datetime_to_string(
        value: datetime | None,
    ) -> str | None:
        """
        Convert datetime to canonical UTC ISO-8601 representation.
        """

        if value is None:
            return None

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # RAW HASH
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_raw_sha256(
        raw_data: bytes,
    ) -> str:
        """
        Calculate SHA-256 over the raw evidence bytes.
        """

        return hashlib.sha256(raw_data).hexdigest()

    # ------------------------------------------------------------------
    # RECORD HASH
    # ------------------------------------------------------------------

    def _calculate_record_hash(
        self,
        *,
        evidence: AuditEvidence,
        capture_id: str | None,
    ) -> str:
        """
        Calculate a deterministic hash over the evidence record.

        The raw bytes themselves are not duplicated in the canonical
        metadata structure. Their SHA-256 is included instead.
        """

        payload = {
            "evidence_id": evidence.evidence_id,
            "capture_id": capture_id,
            "tenant_id": evidence.tenant_id,
            "tenant_hash": evidence.tenant_hash,
            "project_id": evidence.project_id,
            "instance_name": evidence.instance_name,
            "scope": evidence.scope,
            "source": evidence.source,
            "source_path": evidence.source_path,
            "acquisition_layer": evidence.acquisition_layer,
            "acquired_from": evidence.acquired_from,
            "attribution_method": evidence.attribution_method,
            "collected_at": self._datetime_to_string(evidence.collected_at),
            "sha256": self._calculate_raw_sha256(evidence.raw_data),
            "size_bytes": evidence.size_bytes,
            "sequence_start": evidence.sequence_start,
            "sequence_end": evidence.sequence_end,
        }

        return self._hash_canonical_payload(payload)

    @staticmethod
    def _hash_canonical_payload(
        payload: dict[str, Any],
    ) -> str:
        """
        Hash a deterministic JSON representation.
        """

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(canonical).hexdigest()

    # ------------------------------------------------------------------
    # CAPTURE EXISTENCE
    # ------------------------------------------------------------------

    def capture_exists(
        self,
        capture_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:

        sql = """
            SELECT 1
            FROM capture_manifests
            WHERE capture_id = ?
            LIMIT 1
        """

        if connection is not None:
            return (
                connection.execute(
                    sql,
                    (capture_id,),
                ).fetchone()
                is not None
            )

        with self._connect() as conn:
            return (
                conn.execute(
                    sql,
                    (capture_id,),
                ).fetchone()
                is not None
            )

    # ------------------------------------------------------------------
    # SAVE MANIFEST
    # ------------------------------------------------------------------

    def save_manifest(
        self,
        manifest: CaptureManifest,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:

        actual_sha256 = hashlib.sha256(evidence.raw_data).hexdigest()

        if actual_sha256 != evidence.sha256:
            raise ValueError(f"SHA-256 mismatch for " f"{evidence.evidence_id}")

        actual_size = len(evidence.raw_data)

        if actual_size != evidence.size_bytes:
            raise ValueError(f"Evidence size mismatch for " f"{evidence.evidence_id}")

        existing = self.get_evidence_record(evidence.evidence_id)

        if existing is not None:
            if existing.sha256 != evidence.sha256:
                raise ValueError(
                    f"Evidence ID collision with "
                    f"different SHA-256: "
                    f"{evidence.evidence_id}"
                )

        now = self._datetime_to_string(datetime.now(timezone.utc))

        values = (
            manifest.capture_id,
            (
                manifest.status.value
                if hasattr(manifest.status, "value")
                else str(manifest.status)
            ),
            self._datetime_to_string(manifest.started_at),
            self._datetime_to_string(manifest.completed_at),
            len(manifest.sources),
            len(manifest.successful_sources),
            len(manifest.failed_sources),
            now,
            now,
        )

        sql = """
            INSERT INTO capture_manifests (
                capture_id,
                status,
                started_at,
                completed_at,
                requested_source_count,
                successful_source_count,
                failed_source_count,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        if connection is not None:
            connection.execute(
                sql,
                values,
            )
            return

        with self.transaction() as conn:
            conn.execute(
                sql,
                values,
            )

    # ------------------------------------------------------------------
    # UPDATE MANIFEST
    # ------------------------------------------------------------------

    def update_manifest(
        self,
        manifest: CaptureManifest,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:

        now = self._datetime_to_string(datetime.now(timezone.utc))

        values = (
            (
                manifest.status.value
                if hasattr(manifest.status, "value")
                else str(manifest.status)
            ),
            self._datetime_to_string(manifest.completed_at),
            len(manifest.sources),
            len(manifest.successful_sources),
            len(manifest.failed_sources),
            now,
            manifest.capture_id,
        )

        sql = """
            UPDATE capture_manifests
            SET
                status = ?,
                completed_at = ?,
                requested_source_count = ?,
                successful_source_count = ?,
                failed_source_count = ?,
                updated_at = ?
            WHERE capture_id = ?
        """

        if connection is not None:
            result = connection.execute(
                sql,
                values,
            )

            if result.rowcount != 1:
                raise ValueError(
                    "Capture manifest does not exist: " f"{manifest.capture_id}"
                )

            return

        with self.transaction() as conn:
            result = conn.execute(
                sql,
                values,
            )

            if result.rowcount != 1:
                raise ValueError(
                    "Capture manifest does not exist: " f"{manifest.capture_id}"
                )

    # ------------------------------------------------------------------
    # GET MANIFEST
    # ------------------------------------------------------------------

    def get_manifest(
        self,
        capture_id: str,
    ) -> sqlite3.Row | None:

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM capture_manifests
                WHERE capture_id = ?
                """,
                (capture_id,),
            ).fetchone()

    # ------------------------------------------------------------------
    # SAVE AUDIT
    # ------------------------------------------------------------------

    def save_audit(
        self,
        evidence: AuditEvidence,
        *,
        capture_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        """
        Persist an AuditEvidence object.

        This is the compatibility boundary between the audit collector
        and the canonical evidence storage model.
        """

        if capture_id is not None:
            if connection is not None:
                exists = self.capture_exists(
                    capture_id,
                    connection=connection,
                )
            else:
                exists = self.capture_exists(capture_id)

            if not exists:
                raise ValueError(
                    "Cannot persist evidence because capture "
                    f"manifest does not exist: {capture_id}"
                )

        # --------------------------------------------------------------
        # Verify raw evidence before persistence
        # --------------------------------------------------------------

        actual_raw_sha256 = self._calculate_raw_sha256(evidence.raw_data)

        if evidence.sha256 != actual_raw_sha256:
            raise ValueError("Evidence SHA-256 does not match raw_data")

        actual_size = len(evidence.raw_data)

        if evidence.size_bytes != actual_size:
            raise ValueError("Evidence size_bytes does not match " "raw_data length")

        # --------------------------------------------------------------
        # Calculate immutable record hash
        # --------------------------------------------------------------

        record_sha256 = self._calculate_record_hash(
            evidence=evidence,
            capture_id=capture_id,
        )

        # --------------------------------------------------------------
        # Persist
        # --------------------------------------------------------------

        sql = """
            INSERT INTO evidence (
                evidence_id,
                capture_id,

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

                record_sha256
            )
            VALUES (
                ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?,
                ?, ?, ?,
                ?,
                ?, ?, ?,
                ?, ?,
                ?
            )
        """

        values = (
            evidence.evidence_id,
            capture_id,
            evidence.tenant_id,
            evidence.tenant_hash,
            evidence.project_id,
            evidence.instance_name,
            evidence.scope,
            evidence.source,
            evidence.source_path,
            evidence.acquisition_layer,
            evidence.acquired_from,
            evidence.attribution_method,
            self._datetime_to_string(evidence.collected_at),
            sqlite3.Binary(evidence.raw_data),
            actual_raw_sha256,
            actual_size,
            evidence.sequence_start,
            evidence.sequence_end,
            record_sha256,
        )

        if connection is not None:
            connection.execute(
                sql,
                values,
            )
            return evidence.evidence_id

        with self.transaction() as conn:
            conn.execute(
                sql,
                values,
            )

        return evidence.evidence_id

    # ------------------------------------------------------------------
    # GET EVIDENCE
    # ------------------------------------------------------------------

    def get_evidence(
        self,
        evidence_id: str,
    ) -> sqlite3.Row | None:

        with self._connect() as connection:
            return connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()

    # ------------------------------------------------------------------
    # LIST EVIDENCE
    # ------------------------------------------------------------------

    def list_evidence(
        self,
        *,
        capture_id: str | None = None,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        source: str | None = None,
    ) -> list[EvidenceRecord]:

        clauses: list[str] = []
        values: list[Any] = []

        if capture_id is not None:
            clauses.append("capture_id = ?")
            values.append(capture_id)

        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            values.append(tenant_id)

        if instance_name is not None:
            clauses.append("instance_name = ?")
            values.append(instance_name)

        if source is not None:
            clauses.append("source = ?")
            values.append(source)

        sql = """
            SELECT
                evidence_id,
                capture_id,

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

                record_sha256
            FROM evidence
        """

        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        sql += """
            ORDER BY collected_at ASC
    """

        with self._connect() as connection:
            rows = connection.execute(
                sql,
                values,
            ).fetchall()

        return [
            EvidenceRecord(
                evidence_id=row["evidence_id"],
                capture_id=row["capture_id"],
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
                collected_at=datetime.fromisoformat(row["collected_at"]),
                raw_data=bytes(row["raw_data"]),
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                sequence_start=row["sequence_start"],
                sequence_end=row["sequence_end"],
                record_sha256=row["record_sha256"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # COUNT
    # ------------------------------------------------------------------

    def count_evidence(self) -> int:

        with self._connect() as connection:
            row = connection.execute("""
                SELECT COUNT(*) AS count
                FROM evidence
                """).fetchone()

            return int(row["count"])

    # ------------------------------------------------------------------
    # INTEGRITY VERIFICATION
    # ------------------------------------------------------------------

    def verify_evidence_integrity(
        self,
        evidence_id: str,
    ) -> bool:

        details = self.get_integrity_details(evidence_id)

        return bool(
            details["exists"]
            and details["raw_sha256_matches"]
            and details["record_sha256_matches"]
            and details["size_matches"]
        )

    # ------------------------------------------------------------------
    # INTEGRITY DETAILS
    # ------------------------------------------------------------------

    def get_integrity_details(
        self,
        evidence_id: str,
    ) -> dict[str, Any]:

        row = self.get_evidence(evidence_id)

        if row is None:
            return {
                "exists": False,
                "raw_sha256_matches": False,
                "record_sha256_matches": False,
                "size_matches": False,
            }

        raw_data = bytes(row["raw_data"])

        # --------------------------------------------------------------
        # Verify raw payload
        # --------------------------------------------------------------

        calculated_raw_sha256 = self._calculate_raw_sha256(raw_data)

        calculated_size = len(raw_data)

        size_matches = calculated_size == row["size_bytes"]

        raw_sha256_matches = row["sha256"] == calculated_raw_sha256

        # --------------------------------------------------------------
        # Reconstruct canonical metadata
        # --------------------------------------------------------------

        payload = {
            "evidence_id": row["evidence_id"],
            "capture_id": row["capture_id"],
            "tenant_id": row["tenant_id"],
            "tenant_hash": row["tenant_hash"],
            "project_id": row["project_id"],
            "instance_name": row["instance_name"],
            "scope": row["scope"],
            "source": row["source"],
            "source_path": row["source_path"],
            "acquisition_layer": row["acquisition_layer"],
            "acquired_from": row["acquired_from"],
            "attribution_method": row["attribution_method"],
            "collected_at": row["collected_at"],
            "sha256": calculated_raw_sha256,
            "size_bytes": row["size_bytes"],
            "sequence_start": row["sequence_start"],
            "sequence_end": row["sequence_end"],
        }

        calculated_record_sha256 = self._hash_canonical_payload(payload)

        record_sha256_matches = row["record_sha256"] == calculated_record_sha256

        return {
            "exists": True,
            "stored_raw_sha256": row["sha256"],
            "calculated_raw_sha256": calculated_raw_sha256,
            "raw_sha256_matches": raw_sha256_matches,
            "stored_record_sha256": row["record_sha256"],
            "calculated_record_sha256": calculated_record_sha256,
            "record_sha256_matches": record_sha256_matches,
            "stored_size": row["size_bytes"],
            "calculated_size": calculated_size,
            "size_matches": size_matches,
        }

    # ------------------------------------------------------------------
    # EVIDENCE RECORD
    # ------------------------------------------------------------------

    def get_evidence_record(
        self,
        evidence_id: str,
    ) -> EvidenceRecord | None:
        """
        Return persisted evidence as an EvidenceRecord.

        This converts the SQLite representation back into the
        canonical domain representation.
        """

        row = self.get_evidence(evidence_id)

        if row is None:
            return None

        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            capture_id=row["capture_id"],
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
            collected_at=datetime.fromisoformat(row["collected_at"]),
            raw_data=bytes(row["raw_data"]),
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            sequence_start=row["sequence_start"],
            sequence_end=row["sequence_end"],
            record_sha256=row["record_sha256"],
        )
