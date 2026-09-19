from __future__ import annotations

import hashlib
import json
import sqlite3

from evidence.evidence import EvidenceRecord


class GenericEvidenceRepository:
    """
    Repository for canonical raw forensic evidence.

    This repository is intentionally separate from the existing
    EvidenceRepository, which manages normalized EvidenceEvent
    records.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        self.connection = connection

    def get(
        self,
        evidence_id: str,
    ) -> sqlite3.Row | None:
        cursor = self.connection.execute(
            """
            SELECT *
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        )

        return cursor.fetchone()

    def save(
        self,
        evidence: EvidenceRecord,
    ) -> None:

        actual_sha256 = hashlib.sha256(
            evidence.raw_data
        ).hexdigest()

        if actual_sha256 != evidence.sha256:
            raise ValueError(
                f"SHA-256 mismatch for "
                f"{evidence.evidence_id}"
            )

        actual_size = len(
            evidence.raw_data
        )

        if actual_size != evidence.size_bytes:
            raise ValueError(
                f"Evidence size mismatch for "
                f"{evidence.evidence_id}"
            )

        existing = self.get(
            evidence.evidence_id
        )

        if existing is not None:

            if existing["sha256"] != evidence.sha256:
                raise ValueError(
                    "Evidence ID collision with "
                    f"different SHA-256: "
                    f"{evidence.evidence_id}"
                )

            return

        record_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "evidence_id": evidence.evidence_id,
                    "tenant_id": evidence.tenant_id,
                    "tenant_hash": evidence.tenant_hash,
                    "project_id": evidence.project_id,
                    "instance_name": evidence.instance_name,
                    "scope": evidence.scope,
                    "source": evidence.source,
                    "source_path": evidence.source_path,
                    "acquisition_layer": evidence.acquisition_layer,
                    "acquired_from": evidence.acquired_from,
                    "attribution_method": (
                        evidence.attribution_method
                    ),
                    "collected_at": (
                        evidence.collected_at.isoformat()
                    ),
                    "sha256": evidence.sha256,
                    "size_bytes": evidence.size_bytes,
                    "sequence_start": (
                        evidence.sequence_start
                    ),
                    "sequence_end": (
                        evidence.sequence_end
                    ),
                    "capture_id": evidence.capture_id,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        self.connection.execute(
            """
            INSERT INTO evidence_records (
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
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                evidence.evidence_id,
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
                evidence.collected_at.isoformat(),
                evidence.raw_data,
                evidence.sha256,
                evidence.size_bytes,
                evidence.sequence_start,
                evidence.sequence_end,
                evidence.capture_id,
                record_sha256,
            ),
        )

        self.connection.commit()

    def list(
        self,
        *,
        tenant_id: str | None = None,
        instance_name: str | None = None,
    ) -> list[sqlite3.Row]:

        query = """
            SELECT *
            FROM evidence_records
            WHERE 1 = 1
        """

        parameters: list[object] = []

        if tenant_id is not None:
            query += """
                AND tenant_id = ?
            """
            parameters.append(tenant_id)

        if instance_name is not None:
            query += """
                AND instance_name = ?
            """
            parameters.append(instance_name)

        query += """
            ORDER BY collected_at ASC
        """

        cursor = self.connection.execute(
            query,
            parameters,
        )

        return cursor.fetchall()