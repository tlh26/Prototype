from __future__ import annotations

from psycopg import Connection
from psycopg.rows import dict_row

from central.config import CentralConfig


def get_connection(
    config: CentralConfig,
) -> Connection:
    """
    Open a PostgreSQL connection to the central evidence database.

    Connections use dict_row so SELECT results behave similarly
    to the previous sqlite3.Row objects used by the repositories.
    """

    return Connection.connect(
        config.database_url,
        row_factory=dict_row,
    )


def initialise_database(
    config: CentralConfig,
) -> None:
    """
    Verify that the PostgreSQL central evidence schema exists.

    The actual evidence tables are created during the initial
    PostgreSQL deployment/migration. CREATE IF NOT EXISTS is retained
    so application startup remains safe and repeatable.
    """

    with get_connection(config) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    instance_name TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor TEXT,
                    uid INTEGER,
                    resource TEXT,
                    source TEXT NOT NULL,
                    source_path TEXT,
                    details_json TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    agent_id TEXT NOT NULL,
                    raw_data BYTEA NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_tenant
                ON evidence_events(tenant_id)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_instance
                ON evidence_events(
                    tenant_id,
                    instance_name
                )
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_timestamp
                ON evidence_events(timestamp)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_type
                ON evidence_events(evidence_type)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_hash
                ON evidence_events(sha256)
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
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
                    raw_data BYTEA NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sequence_start INTEGER,
                    sequence_end INTEGER,
                    capture_id TEXT,
                    record_sha256 TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_records_tenant
                ON evidence_records(tenant_id)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_records_instance
                ON evidence_records(instance_name)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_records_source
                ON evidence_records(source)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_evidence_records_collected_at
                ON evidence_records(collected_at)
                """
            )

        connection.commit()