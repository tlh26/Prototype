from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from central.database import CentralDatabase
from central.storage import RawEvidenceStore

app = FastAPI(
    title="Central Evidence Storage",
    version="1.0.0",
)

database = CentralDatabase("data/central.db")

store = RawEvidenceStore("/srv/evidence-objects")

API_KEY = os.getenv(
    "EVIDENCE_API_KEY",
    "change-me",
)


class EvidenceSubmission(BaseModel):

    event_id: str

    tenant_id: str
    instance_name: str

    evidence_type: str
    event_type: str

    timestamp: str

    actor: str | None = None

    uid: int | None = None

    resource: str | None = None

    source: str
    source_path: str | None = None

    sequence: int

    agent_id: str

    raw_data: str

    sha256: str

    created_at: str


@app.post("/api/v1/evidence")
def submit_evidence(
    submission: EvidenceSubmission,
    authorization: str | None = Header(default=None),
):

    expected = f"Bearer {API_KEY}"

    if authorization != expected:

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication",
        )

    raw_data = submission.raw_data.encode("utf-8")

    calculated = hashlib.sha256(raw_data).hexdigest()

    if calculated != submission.sha256:

        raise HTTPException(
            status_code=400,
            detail="Evidence SHA-256 mismatch",
        )

    object_key, object_hash = store.put(
        tenant_id=submission.tenant_id,
        instance_name=submission.instance_name,
        evidence_type=submission.evidence_type,
        raw_data=raw_data,
        expected_sha256=submission.sha256,
    )

    canonical = {
        "event_id": submission.event_id,
        "tenant_id": submission.tenant_id,
        "instance_name": submission.instance_name,
        "agent_id": submission.agent_id,
        "evidence_type": submission.evidence_type,
        "event_type": submission.event_type,
        "timestamp": submission.timestamp,
        "source": submission.source,
        "source_path": submission.source_path,
        "sequence": submission.sequence,
        "object_key": object_key,
        "sha256": submission.sha256,
        "size_bytes": len(raw_data),
    }

    record_sha256 = hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    received_at = datetime.now(timezone.utc).isoformat()

    with database.connect() as db:

        try:

            db.execute(
                """
                INSERT INTO evidence (
                    evidence_id,
                    tenant_id,
                    instance_name,
                    agent_id,
                    evidence_type,
                    event_type,
                    event_timestamp,
                    source,
                    source_path,
                    sequence,
                    object_key,
                    sha256,
                    size_bytes,
                    received_at,
                    record_sha256
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    submission.event_id,
                    submission.tenant_id,
                    submission.instance_name,
                    submission.agent_id,
                    submission.evidence_type,
                    submission.event_type,
                    submission.timestamp,
                    submission.source,
                    submission.source_path,
                    submission.sequence,
                    object_key,
                    object_hash,
                    len(raw_data),
                    received_at,
                    record_sha256,
                ),
            )

        except Exception as exc:

            if "UNIQUE constraint" in str(exc):

                return {
                    "status": "duplicate",
                    "evidence_id": submission.event_id,
                    "sha256": submission.sha256,
                    "object_key": object_key,
                }

            raise

    return {
        "status": "stored",
        "evidence_id": submission.event_id,
        "sha256": submission.sha256,
        "object_key": object_key,
        "record_sha256": record_sha256,
    }
