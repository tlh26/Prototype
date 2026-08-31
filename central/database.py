from __future__ import annotations

import sqlite3
from pathlib import Path


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