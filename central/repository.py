import json
import sqlite3

from evidenceAgent.evidenceAgent.models import EvidenceEvent


class EvidenceRepository:

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def save(self, event: EvidenceEvent) -> None:
        self.connection.execute(
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.event_id),
                event.tenant_id,
                event.instance_name,
                event.evidence_type.value,
                event.event_type.value,
                event.timestamp.isoformat(),
                event.actor,
                event.uid,
                event.resource,
                event.source,
                event.source_path,
                json.dumps(
                    event.details,
                    sort_keys=True,
                ),
                event.sequence,
                event.agent_id,
                event.raw_data,
                event.sha256,
                event.created_at.isoformat(),
            ),
        )

        self.connection.commit()

    def get(self, event_id: str):
        return self.connection.execute(
            """
            SELECT *
            FROM evidence_events
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()

    def list(
        self,
        tenant_id: str | None = None,
        instance_name: str | None = None,
    ):
        query = """
            SELECT *
            FROM evidence_events
            WHERE 1 = 1
        """

        parameters = []

        if tenant_id:
            query += " AND tenant_id = ?"
            parameters.append(tenant_id)

        if instance_name:
            query += " AND instance_name = ?"
            parameters.append(instance_name)

        query += """
            ORDER BY timestamp ASC, sequence ASC
        """

        return self.connection.execute(
            query,
            parameters,
        ).fetchall()