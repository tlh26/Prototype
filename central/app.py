from __future__ import annotations

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
from central.genericRepo import GenericEvidenceRepository
from central.ingest import IngestionError, ingest_batch
from evidenceAgent.evidenceAgent.transportModels import EvidenceBatch

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
        "database": "postgresql",
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

    calculated_hash = hashlib.sha256(raw_data).hexdigest()

    if calculated_hash != request.sha256:
        raise HTTPException(
            status_code=400,
            detail="SHA-256 integrity verification failed",
        )

    connection = get_connection(config)

    try:
        repository = EvidenceRepository(connection)

        existing = repository.get(request.event_id)

        if existing:
            return {
                "status": "already_exists",
                "event_id": request.event_id,
            }

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
            VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s
            )
            """,
            (
                request.event_id,
                request.tenant_id,
                request.instance_name,
                request.evidence_type,
                request.event_type,
                request.timestamp.isoformat(),
                request.actor,
                request.uid,
                request.resource,
                request.source,
                request.source_path,
                json.dumps(
                    request.details,
                    sort_keys=True,
                ),
                request.sequence,
                request.agent_id,
                raw_data,
                request.sha256,
                request.created_at.isoformat(),
            ),
        )

        connection.commit()

        return {
            "status": "stored",
            "event_id": request.event_id,
            "sha256": request.sha256,
        }

    except Exception:
        connection.rollback()
        raise

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
        repository = EvidenceRepository(connection)

        rows = repository.list(
            tenant_id=tenant_id,
            instance_name=instance_name,
        )

        return {
            "count": len(rows),
            "events": rows,
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
        repository = EvidenceRepository(connection)

        row = repository.get(event_id)

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Evidence event not found",
            )

        event = dict(row)

        event["raw_data"] = base64.b64encode(bytes(event["raw_data"])).decode("ascii")

        return event

    finally:
        connection.close()


@app.post("/api/v1/evidence/batches")
def submit_batch(
    batch: EvidenceBatch,
    x_api_key: str | None = Header(default=None),
):
    verify_api_key(
        x_api_key,
        config,
    )

    connection = get_connection(config)

    try:
        repository = GenericEvidenceRepository(connection)

        try:
            stored = ingest_batch(
                batch=batch,
                repository=repository,
            )

        except IngestionError as exc:
            connection.rollback()

            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        except ValueError as exc:
            connection.rollback()

            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        return {
            "status": "accepted",
            "agent_id": batch.agent_id,
            "received": len(batch.evidence),
            "stored": stored,
        }

    finally:
        connection.close()
