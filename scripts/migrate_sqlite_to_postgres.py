from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path

import psycopg


SQLITE_PATH = Path("storage/evidence.db")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def migrate_events(sqlite_conn, pg_conn):
    print("Migrating evidence_events...")

    sqlite_cursor = sqlite_conn.execute(
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
        ORDER BY rowid
        """
    )

    count = 0

    try:
        with pg_conn.cursor() as pg_cursor:
            for row in sqlite_cursor:
                (
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
                    created_at,
                ) = row

                # SQLite BLOB -> Python bytes
                raw_data = bytes(raw_data)

                # Verify evidence integrity before migration.
                calculated_sha256 = sha256_bytes(raw_data)

                if calculated_sha256 != sha256:
                    raise RuntimeError(
                        f"SHA-256 mismatch for evidence_event {event_id}: "
                        f"stored={sha256}, calculated={calculated_sha256}"
                    )

                pg_cursor.execute(
                    """
                    INSERT INTO evidence_events (
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
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
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
                        created_at,
                    ),
                )

                count += 1

                if count % 250 == 0:
                    print(f"  migrated {count} evidence events...")

    finally:
        sqlite_cursor.close()

    print(f"evidence_events complete: {count} rows")


def migrate_records(sqlite_conn, pg_conn):
    print("Migrating evidence_records...")

    sqlite_cursor = sqlite_conn.execute(
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
        ORDER BY rowid
        """
    )

    count = 0

    try:
        with pg_conn.cursor() as pg_cursor:
            for row in sqlite_cursor:
                (
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
                    record_sha256,
                ) = row

                # SQLite BLOB -> Python bytes
                raw_data = bytes(raw_data)

                # Verify evidence integrity before migration.
                calculated_sha256 = sha256_bytes(raw_data)

                if calculated_sha256 != sha256:
                    raise RuntimeError(
                        f"SHA-256 mismatch for evidence_record {evidence_id}: "
                        f"stored={sha256}, calculated={calculated_sha256}"
                    )

                pg_cursor.execute(
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
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    ON CONFLICT (evidence_id) DO NOTHING
                    """,
                    (
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
                        record_sha256,
                    ),
                )

                count += 1

                if count % 500 == 0:
                    print(f"  migrated {count} evidence records...")

    finally:
        sqlite_cursor.close()

    print(f"evidence_records complete: {count} rows")


def main():
    if not SQLITE_PATH.exists():
        raise FileNotFoundError(
            f"SQLite database not found: {SQLITE_PATH}"
        )

    postgres_url = os.environ.get("CENTRAL_DATABASE_URL")

    if not postgres_url:
        raise RuntimeError(
            "CENTRAL_DATABASE_URL is not set."
        )

    print("Connecting to PostgreSQL...")

    sqlite_conn = sqlite3.connect(SQLITE_PATH)

    try:
        with psycopg.connect(postgres_url) as pg_conn:
            print("PostgreSQL connection established.")

            migrate_events(sqlite_conn, pg_conn)
            migrate_records(sqlite_conn, pg_conn)

            pg_conn.commit()

            print()
            print("========================================")
            print("Migration committed successfully.")
            print("========================================")

    except Exception:
        print()
        print("Migration failed. PostgreSQL transaction will be rolled back.")
        raise

    finally:
        sqlite_conn.close()


if __name__ == "__main__":
    main()