from __future__ import annotations

import sqlite3
from pathlib import Path
from central.config import CentralConfig

class CentralDatabase:

    def __init__(
        self,
        path: str = "data/central.db",
    ):

        self.path = Path(path)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    def connect(self):

        connection = sqlite3.connect(
            self.path
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize(self):

        with self.connect() as db:

            db.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,

                    tenant_id TEXT NOT NULL,

                    instance_name TEXT NOT NULL,

                    agent_id TEXT NOT NULL,

                    evidence_type TEXT NOT NULL,

                    event_type TEXT NOT NULL,

                    event_timestamp TEXT NOT NULL,

                    source TEXT NOT NULL,

                    source_path TEXT,

                    sequence INTEGER NOT NULL,

                    object_key TEXT NOT NULL,

                    sha256 TEXT NOT NULL,

                    size_bytes INTEGER NOT NULL,

                    received_at TEXT NOT NULL,

                    record_sha256 TEXT NOT NULL,

                    UNIQUE (
                        tenant_id,
                        agent_id,
                        sequence
                    )
                )
                """
            )

            db.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_central_tenant
                ON evidence(tenant_id)
                """
            )

            db.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_central_instance
                ON evidence(instance_name)
                """
            )

            db.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_central_hash
                ON evidence(sha256)
                """
            )

            db.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_central_event_type
                ON evidence(event_type)
                """
            )


def get_connection(config: CentralConfig) -> sqlite3.Connection:
    path = Path(config.database_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        path,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialise_database(config: CentralConfig) -> None:
    connection = get_connection(config)

    try:
        connection.executescript(
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
                raw_data BLOB NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
                idx_evidence_tenant
            ON evidence_events(tenant_id);

            CREATE INDEX IF NOT EXISTS
                idx_evidence_instance
            ON evidence_events(
                tenant_id,
                instance_name
            );

            CREATE INDEX IF NOT EXISTS
                idx_evidence_timestamp
            ON evidence_events(timestamp);

            CREATE INDEX IF NOT EXISTS
                idx_evidence_type
            ON evidence_events(evidence_type);

            CREATE INDEX IF NOT EXISTS
                idx_evidence_hash
            ON evidence_events(sha256);
            """
        )

        connection.commit()

    finally:
        connection.close()