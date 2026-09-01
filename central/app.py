import base64
import hashlib
import json

from fastapi import FastAPI, Header, HTTPException

from central.config import CentralConfig
from central.database import (
    get_connection,
    initialise_database,
)
from central.repository import EvidenceRepository
from central.schemas import EvidenceEventRequest
from central.security import verify_api_key


config = CentralConfig()

initialise_database(config)

app = FastAPI(
    title="Evidence Central API",
    version="0.1.0",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "evidence-central",
    }


@app.post("/api/v1/evidence/events")
def submit_event(
    request: EvidenceEventRequest,
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(
        x_api_key,
        config,
    )

    try:
        raw_data = base64.b64decode(
            request.raw_data,
            validate=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid raw_data encoding",
        ) from exc

    calculated_hash = hashlib.sha256(
        raw_data
    ).hexdigest()

    if calculated_hash != request.sha256:
        raise HTTPException(
            status_code=400,
            detail="SHA-256 integrity verification failed",
        )

    connection = get_connection(config)

    try:
        repository = EvidenceRepository(
            connection
        )

        existing = repository.get(
            request.event_id
        )

        if existing:
            return {
                "status": "already_exists",
                "event_id": request.event_id,
            }

        event = request

        connection.execute(
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
                event.event_id,
                event.tenant_id,
                event.instance_name,
                event.evidence_type,
                event.event_type,
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
                raw_data,
                event.sha256,
                event.created_at.isoformat(),
            ),
        )

        connection.commit()

        return {
            "status": "stored",
            "event_id": event.event_id,
            "sha256": event.sha256,
        }

    finally:
        connection.close()


@app.get("/api/v1/evidence/events")
def list_events(
    tenant_id: str | None = None,
    instance_name: str | None = None,
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(
        x_api_key,
        config,
    )

    connection = get_connection(config)

    try:
        repository = EvidenceRepository(
            connection
        )

        rows = repository.list(
            tenant_id=tenant_id,
            instance_name=instance_name,
        )

        return {
            "count": len(rows),
            "events": [
                dict(row)
                for row in rows
            ],
        }

    finally:
        connection.close()


@app.get("/api/v1/evidence/events/{event_id}")
def get_event(
    event_id: str,
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(
        x_api_key,
        config,
    )

    connection = get_connection(config)

    try:
        repository = EvidenceRepository(
            connection
        )

        row = repository.get(event_id)

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Evidence event not found",
            )

        event = dict(row)

        # SQLite stores raw evidence as BLOB.
        # The API exposes it as Base64 so that the
        # original bytes can safely travel through JSON.
        event["raw_data"] = base64.b64encode(
            event["raw_data"]
        ).decode("ascii")

        return event

    finally:
        connection.close()