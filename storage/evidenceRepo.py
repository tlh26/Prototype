from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from acquisition.captureManifest import CaptureManifest
from acquisition.collectors.audit import AuditEvidence


class SQLiteEvidenceRepository:
    """
    SQLite-backed repository for acquired forensic evidence.

    The repository stores:

        - raw evidence bytes
        - SHA-256 of raw evidence
        - evidence metadata
        - tenant information
        - acquisition information
        - capture manifests
        - record-level integrity hash

    SQLite is used as the prototype persistence layer.

    Integrity model:

        raw evidence
            |
            +-- SHA-256 --> evidence.sha256

        evidence metadata + evidence.sha256
            |
            +-- SHA-256 --> evidence.record_sha256

    Evidence records are INSERT-only.

    Capture manifests have a lifecycle:

        create
          |
          v
        save_manifest()
          |
          v
        acquisition
          |
          v
        update_manifest()
          |
          v
        completed manifest
    """

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:

        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    # ==================================================================
    # Database connection / transactions
    # ==================================================================

    def _connect(self) -> sqlite3.Connection:
        """
        Create a SQLite connection with foreign-key enforcement enabled.
        """

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    @contextmanager
    def transaction(
        self,
    ) -> Iterator[sqlite3.Connection]:
        """
        Provide an explicit transaction boundary.

        This allows callers such as EvidenceCaptureService to perform
        multiple persistence operations atomically.

        Example:

            with repository.transaction() as connection:

                repository.save_manifest(
                    manifest,
                    connection=connection,
                )

                repository.save_audit(
                    evidence,
                    capture_id=manifest.capture_id,
                    connection=connection,
                )

        If an exception occurs, the transaction is rolled back.
        Otherwise it is committed.
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

    # ==================================================================
    # Database initialization
    # ==================================================================

    def _initialize_database(self) -> None:

        with self._connect() as connection:

            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS capture_manifests (
                    capture_id TEXT PRIMARY KEY,

                    tenant_id TEXT NOT NULL,

                    tenant_hash TEXT NOT NULL,

                    project_id TEXT NOT NULL,

                    instance_name TEXT NOT NULL,

                    started_at TEXT NOT NULL,

                    completed_at TEXT,

                    status TEXT NOT NULL,

                    source_count INTEGER NOT NULL,

                    evidence_count INTEGER NOT NULL,

                    manifest_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,

                    capture_id TEXT,

                    tenant_id TEXT NOT NULL,

                    tenant_hash TEXT NOT NULL,

                    project_id TEXT NOT NULL,

                    instance_name TEXT NOT NULL,

                    source TEXT NOT NULL,

                    source_path TEXT NOT NULL,

                    collected_at TEXT NOT NULL,

                    raw_data BLOB NOT NULL,

                    sha256 TEXT NOT NULL,

                    size_bytes INTEGER NOT NULL,

                    sequence_start INTEGER,

                    sequence_end INTEGER,

                    record_sha256 TEXT NOT NULL,

                    FOREIGN KEY (capture_id)
                        REFERENCES capture_manifests(capture_id)
                );

                CREATE INDEX IF NOT EXISTS
                    idx_evidence_tenant
                ON evidence(tenant_id);

                CREATE INDEX IF NOT EXISTS
                    idx_evidence_instance
                ON evidence(instance_name);

                CREATE INDEX IF NOT EXISTS
                    idx_evidence_source
                ON evidence(source);

                CREATE INDEX IF NOT EXISTS
                    idx_evidence_capture
                ON evidence(capture_id);

                CREATE INDEX IF NOT EXISTS
                    idx_evidence_sha256
                ON evidence(sha256);
                """
            )

    # ==================================================================
    # Utility functions
    # ==================================================================

    @staticmethod
    def _datetime_to_string(
        value: datetime | None,
    ) -> str | None:

        if value is None:
            return None

        return value.isoformat()

    @staticmethod
    def _calculate_raw_sha256(
        raw_data: bytes,
    ) -> str:
        """
        Calculate SHA-256 directly from raw evidence bytes.
        """

        return hashlib.sha256(
            raw_data
        ).hexdigest()

    @staticmethod
    def _calculate_record_hash(
        *,
        evidence: AuditEvidence,
        capture_id: str | None,
    ) -> str:
        """
        Calculate a deterministic integrity hash over the evidence
        metadata and the SHA-256 of the raw evidence.

        The raw evidence itself is represented by evidence.sha256.
        """

        canonical_record = {
            "evidence_id": evidence.evidence_id,
            "capture_id": capture_id,
            "tenant_id": evidence.tenant_id,
            "tenant_hash": evidence.tenant_hash,
            "project_id": evidence.project_id,
            "instance_name": evidence.instance_name,
            "source": evidence.source,
            "source_path": evidence.source_path,
            "collected_at": evidence.collected_at.isoformat(),
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
            "sequence_start": evidence.sequence_start,
            "sequence_end": evidence.sequence_end,
        }

        serialized = json.dumps(
            canonical_record,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            serialized
        ).hexdigest()

    # ==================================================================
    # Capture manifest persistence
    # ==================================================================

    def capture_exists(
        self,
        capture_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        """
        Determine whether a capture manifest already exists.
        """

        owns_connection = connection is None

        if owns_connection:
            connection = self._connect()

        try:

            cursor = connection.execute(
                """
                SELECT 1
                FROM capture_manifests
                WHERE capture_id = ?
                LIMIT 1
                """,
                (capture_id,),
            )

            return cursor.fetchone() is not None

        finally:

            if owns_connection:
                connection.close()

    def save_manifest(
        self,
        manifest: CaptureManifest,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """
        Insert a new capture manifest.

        This method intentionally uses INSERT rather than
        INSERT OR REPLACE.

        A capture ID should normally only be created once.
        """

        manifest_json = manifest.model_dump_json(
            exclude_none=False
        )

        owns_connection = connection is None

        if owns_connection:
            connection = self._connect()

        try:

            connection.execute(
                """
                INSERT INTO capture_manifests (
                    capture_id,
                    tenant_id,
                    tenant_hash,
                    project_id,
                    instance_name,
                    started_at,
                    completed_at,
                    status,
                    source_count,
                    evidence_count,
                    manifest_json
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    manifest.capture_id,
                    manifest.tenant_id,
                    manifest.tenant_hash,
                    manifest.project_id,
                    manifest.instance_name,
                    manifest.started_at.isoformat(),
                    self._datetime_to_string(
                        manifest.completed_at
                    ),
                    manifest.status.value,
                    len(manifest.sources),
                    manifest.evidence_count,
                    manifest_json,
                ),
            )

            if owns_connection:
                connection.commit()

        except Exception:

            if owns_connection:
                connection.rollback()

            raise

        finally:

            if owns_connection:
                connection.close()

    def update_manifest(
        self,
        manifest: CaptureManifest,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """
        Update an existing capture manifest.

        This is used after evidence acquisition has completed and the
        final source results, completion time and overall capture status
        are known.

        The capture_id itself is never changed.

        Unlike evidence records, capture manifests represent the
        lifecycle state of an acquisition operation, so updating the
        existing manifest is intentional.
        """

        manifest_json = manifest.model_dump_json(
            exclude_none=False
        )

        owns_connection = connection is None

        if owns_connection:
            connection = self._connect()

        try:

            cursor = connection.execute(
                """
                UPDATE capture_manifests
                SET
                    tenant_id = ?,
                    tenant_hash = ?,
                    project_id = ?,
                    instance_name = ?,
                    started_at = ?,
                    completed_at = ?,
                    status = ?,
                    source_count = ?,
                    evidence_count = ?,
                    manifest_json = ?
                WHERE capture_id = ?
                """,
                (
                    manifest.tenant_id,
                    manifest.tenant_hash,
                    manifest.project_id,
                    manifest.instance_name,
                    manifest.started_at.isoformat(),
                    self._datetime_to_string(
                        manifest.completed_at
                    ),
                    manifest.status.value,
                    len(manifest.sources),
                    manifest.evidence_count,
                    manifest_json,
                    manifest.capture_id,
                ),
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    "Cannot update unknown capture manifest: "
                    f"{manifest.capture_id}"
                )

            if owns_connection:
                connection.commit()

        except Exception:

            if owns_connection:
                connection.rollback()

            raise

        finally:

            if owns_connection:
                connection.close()

    def get_manifest(
        self,
        capture_id: str,
    ) -> sqlite3.Row | None:
        """
        Retrieve a capture manifest by capture ID.
        """

        with self._connect() as connection:

            cursor = connection.execute(
                """
                SELECT *
                FROM capture_manifests
                WHERE capture_id = ?
                """,
                (capture_id,),
            )

            return cursor.fetchone()

    # ==================================================================
    # Evidence persistence
    # ==================================================================

    def save_audit(
        self,
        evidence: AuditEvidence,
        *,
        capture_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> str:
        """
        Persist AuditEvidence.

        Before persistence, the repository independently recalculates
        SHA-256 from the raw evidence and compares it with the hash
        supplied by the collector.

        Integrity boundary:

            Collector
                |
                | evidence.sha256
                v
            Repository
                |
                | SHA-256(raw_data)
                v
              Compare
                |
                +-- match --> persist
                |
                +-- mismatch --> reject
        """

        # --------------------------------------------------------------
        # Validate evidence size
        # --------------------------------------------------------------

        actual_size = len(
            evidence.raw_data
        )

        if actual_size != evidence.size_bytes:

            raise ValueError(
                "Evidence size does not match raw_data: "
                f"expected {evidence.size_bytes}, "
                f"actual {actual_size}"
            )

        # --------------------------------------------------------------
        # Independently verify raw evidence SHA-256
        # --------------------------------------------------------------

        calculated_sha256 = (
            self._calculate_raw_sha256(
                evidence.raw_data
            )
        )

        if calculated_sha256 != evidence.sha256:

            raise ValueError(
                "Evidence SHA-256 verification failed: "
                f"expected {evidence.sha256}, "
                f"calculated {calculated_sha256}"
            )

        # --------------------------------------------------------------
        # Calculate record-level integrity hash
        # --------------------------------------------------------------

        record_sha256 = (
            self._calculate_record_hash(
                evidence=evidence,
                capture_id=capture_id,
            )
        )

        owns_connection = connection is None

        if owns_connection:
            connection = self._connect()

        try:

            # ----------------------------------------------------------
            # Verify capture relationship
            # ----------------------------------------------------------

            if capture_id is not None:

                cursor = connection.execute(
                    """
                    SELECT 1
                    FROM capture_manifests
                    WHERE capture_id = ?
                    LIMIT 1
                    """,
                    (capture_id,),
                )

                if cursor.fetchone() is None:

                    raise ValueError(
                        "Cannot save evidence for unknown "
                        f"capture_id: {capture_id}"
                    )

            # ----------------------------------------------------------
            # Insert evidence
            # ----------------------------------------------------------

            connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id,
                    capture_id,
                    tenant_id,
                    tenant_hash,
                    project_id,
                    instance_name,
                    source,
                    source_path,
                    collected_at,
                    raw_data,
                    sha256,
                    size_bytes,
                    sequence_start,
                    sequence_end,
                    record_sha256
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    evidence.evidence_id,
                    capture_id,
                    evidence.tenant_id,
                    evidence.tenant_hash,
                    evidence.project_id,
                    evidence.instance_name,
                    evidence.source,
                    evidence.source_path,
                    evidence.collected_at.isoformat(),
                    sqlite3.Binary(
                        evidence.raw_data
                    ),
                    evidence.sha256,
                    evidence.size_bytes,
                    evidence.sequence_start,
                    evidence.sequence_end,
                    record_sha256,
                ),
            )

            if owns_connection:
                connection.commit()

        except Exception:

            if owns_connection:
                connection.rollback()

            raise

        finally:

            if owns_connection:
                connection.close()

        return evidence.evidence_id

    # ==================================================================
    # Evidence retrieval
    # ==================================================================

    def get_evidence(
        self,
        evidence_id: str,
    ) -> sqlite3.Row | None:
        """
        Retrieve one evidence record.
        """

        with self._connect() as connection:

            cursor = connection.execute(
                """
                SELECT *
                FROM evidence
                WHERE evidence_id = ?
                """,
                (evidence_id,),
            )

            return cursor.fetchone()

    def list_evidence(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
        source: str | None = None,
    ) -> list[sqlite3.Row]:
        """
        List evidence records using optional tenant, instance and
        source filters.
        """

        query = """
            SELECT *
            FROM evidence
            WHERE 1 = 1
        """

        parameters: list[Any] = []

        if tenant_id is not None:

            query += """
                AND tenant_id = ?
            """

            parameters.append(
                tenant_id
            )

        if instance_name is not None:

            query += """
                AND instance_name = ?
            """

            parameters.append(
                instance_name
            )

        if source is not None:

            query += """
                AND source = ?
            """

            parameters.append(
                source
            )

        query += """
            ORDER BY collected_at ASC
        """

        with self._connect() as connection:

            cursor = connection.execute(
                query,
                parameters,
            )

            return cursor.fetchall()

    def count_evidence(self) -> int:
        """
        Return the total number of evidence records.
        """

        with self._connect() as connection:

            cursor = connection.execute(
                """
                SELECT COUNT(*)
                FROM evidence
                """
            )

            return int(
                cursor.fetchone()[0]
            )

    # ==================================================================
    # Integrity verification
    # ==================================================================

    def verify_evidence_integrity(
        self,
        evidence_id: str,
    ) -> bool:
        """
        Verify both integrity levels for one stored evidence record.

        Level 1:
            SHA-256(raw_data) == stored sha256

        Level 2:
            SHA-256(canonical metadata) == stored record_sha256

        Returns True only if both checks succeed.
        """

        row = self.get_evidence(
            evidence_id
        )

        if row is None:

            raise ValueError(
                f"Evidence not found: {evidence_id}"
            )

        raw_data = bytes(
            row["raw_data"]
        )

        # --------------------------------------------------------------
        # Level 1: raw evidence integrity
        # --------------------------------------------------------------

        calculated_raw_sha256 = (
            self._calculate_raw_sha256(
                raw_data
            )
        )

        raw_integrity_ok = (
            calculated_raw_sha256
            == row["sha256"]
        )

        if not raw_integrity_ok:
            return False

        # --------------------------------------------------------------
        # Reconstruct evidence model
        # --------------------------------------------------------------

        collected_at = datetime.fromisoformat(
            row["collected_at"]
        )

        evidence = AuditEvidence(
            evidence_id=row["evidence_id"],
            tenant_id=row["tenant_id"],
            tenant_hash=row["tenant_hash"],
            project_id=row["project_id"],
            instance_name=row["instance_name"],
            scope=(
                f"{row['project_id']}/"
                f"{row['instance_name']}"
            ),
            source=row["source"],
            source_path=row["source_path"],
            collected_at=collected_at,
            raw_data=raw_data,
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            sequence_start=row["sequence_start"],
            sequence_end=row["sequence_end"],
        )

        # --------------------------------------------------------------
        # Level 2: record metadata integrity
        # --------------------------------------------------------------

        calculated_record_sha256 = (
            self._calculate_record_hash(
                evidence=evidence,
                capture_id=row["capture_id"],
            )
        )

        record_integrity_ok = (
            calculated_record_sha256
            == row["record_sha256"]
        )

        return (
            raw_integrity_ok
            and record_integrity_ok
        )

    def get_integrity_details(
        self,
        evidence_id: str,
    ) -> dict[str, Any]:
        """
        Return detailed integrity verification information.

        Intended for prototype evaluation, testing and dashboard use.
        """

        row = self.get_evidence(
            evidence_id
        )

        if row is None:

            raise ValueError(
                f"Evidence not found: {evidence_id}"
            )

        raw_data = bytes(
            row["raw_data"]
        )

        # --------------------------------------------------------------
        # Raw evidence SHA-256
        # --------------------------------------------------------------

        calculated_raw_sha256 = (
            self._calculate_raw_sha256(
                raw_data
            )
        )

        raw_hash_match = (
            calculated_raw_sha256
            == row["sha256"]
        )

        # --------------------------------------------------------------
        # Reconstruct evidence object
        # --------------------------------------------------------------

        evidence = AuditEvidence(
            evidence_id=row["evidence_id"],
            tenant_id=row["tenant_id"],
            tenant_hash=row["tenant_hash"],
            project_id=row["project_id"],
            instance_name=row["instance_name"],
            scope=(
                f"{row['project_id']}/"
                f"{row['instance_name']}"
            ),
            source=row["source"],
            source_path=row["source_path"],
            collected_at=datetime.fromisoformat(
                row["collected_at"]
            ),
            raw_data=raw_data,
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            sequence_start=row["sequence_start"],
            sequence_end=row["sequence_end"],
        )

        # --------------------------------------------------------------
        # Record SHA-256
        # --------------------------------------------------------------

        calculated_record_sha256 = (
            self._calculate_record_hash(
                evidence=evidence,
                capture_id=row["capture_id"],
            )
        )

        record_hash_match = (
            calculated_record_sha256
            == row["record_sha256"]
        )

        return {
            "evidence_id": row["evidence_id"],

            "raw_sha256_stored":
                row["sha256"],

            "raw_sha256_calculated":
                calculated_raw_sha256,

            "raw_sha256_match":
                raw_hash_match,

            "record_sha256_stored":
                row["record_sha256"],

            "record_sha256_calculated":
                calculated_record_sha256,

            "record_sha256_match":
                record_hash_match,

            "integrity_verified":
                (
                    raw_hash_match
                    and record_hash_match
                ),
        }