from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from central import app as app_module
from central.database import initialise_database
from evidenceAgent.evidenceAgent.transportModels import (
    EvidenceBatch,
    EvidenceEnvelope,
)


@pytest.fixture
def test_config(tmp_path):
    return SimpleNamespace(
        database_path=str(
            tmp_path / "central-test.db"
        ),
    )


@pytest.fixture
def client(
    test_config,
    monkeypatch,
):
    """
    Create a FastAPI TestClient using an isolated SQLite database.
    """

    initialise_database(test_config)

    monkeypatch.setattr(
        app_module,
        "config",
        test_config,
    )

    monkeypatch.setattr(
        app_module,
        "get_connection",
        lambda config: __import__(
            "central.database",
            fromlist=["get_connection"],
        ).get_connection(config),
    )

    return TestClient(
        app_module.app
    )


def make_envelope(
    *,
    evidence_id: str = "auditd:100",
    raw_data: bytes = b"test audit evidence",
    tenant_id: str | None = "tenant-b",
    instance_name: str | None = "web-b",
    sequence_start: int | None = 100,
    sequence_end: int | None = 100,
) -> EvidenceEnvelope:
    """
    Create a valid transport envelope for testing.
    """

    return EvidenceEnvelope(
        evidence_id=evidence_id,

        tenant_id=tenant_id,
        tenant_hash=None,

        project_id=tenant_id,
        instance_name=instance_name,

        scope=(
            f"{tenant_id}/{instance_name}"
            if tenant_id and instance_name
            else "incus-host-01"
        ),

        source="auditd",
        source_path="/var/log/audit/audit.log",

        acquisition_layer="host",
        acquired_from="incus-host-01",

        attribution_method=(
            "incus_metadata"
            if tenant_id
            else "unattributed"
        ),

        collected_at=datetime.now(
            timezone.utc
        ),

        raw_data_b64=base64.b64encode(
            raw_data
        ).decode("ascii"),

        sha256=hashlib.sha256(
            raw_data
        ).hexdigest(),

        size_bytes=len(raw_data),

        sequence_start=sequence_start,
        sequence_end=sequence_end,

        capture_id="capture-test-001",
    )


def make_batch(
    *envelopes: EvidenceEnvelope,
) -> EvidenceBatch:
    """
    Create a valid EvidenceBatch.
    """

    return EvidenceBatch(
        agent_id="agent-host-test",
        evidence=tuple(envelopes),
    )


def test_health_endpoint(
    client: TestClient,
    monkeypatch,
):
    """
    Verify that the existing health endpoint remains functional.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "service": "evidence-central",
    }


def test_submit_valid_evidence_batch(
    client: TestClient,
    test_config,
    monkeypatch,
):
    """
    A valid EvidenceBatch should be accepted by the new endpoint.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    raw_data = (
        b"type=SYSCALL "
        b"msg=audit(123.456:100): "
        b"test"
    )

    envelope = make_envelope(
        raw_data=raw_data
    )

    batch = make_batch(
        envelope
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "accepted"
    assert body["agent_id"] == (
        "agent-host-test"
    )
    assert body["received"] == 1
    assert body["stored"] == 1


def test_valid_evidence_is_persisted(
    client: TestClient,
    test_config,
    monkeypatch,
):
    """
    Verify that accepted evidence actually reaches SQLite.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    raw_data = b"raw forensic audit evidence"

    envelope = make_envelope(
        raw_data=raw_data
    )

    batch = make_batch(
        envelope
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 200

    connection = app_module.get_connection(
        test_config
    )

    try:
        row = connection.execute(
            """
            SELECT *
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (
                envelope.evidence_id,
            ),
        ).fetchone()

    finally:
        connection.close()

    assert row is not None

    assert row["evidence_id"] == (
        envelope.evidence_id
    )

    assert row["tenant_id"] == "tenant-b"
    assert row["project_id"] == "tenant-b"
    assert row["instance_name"] == "web-b"

    assert row["source"] == "auditd"

    assert row["raw_data"] == raw_data

    assert row["sha256"] == hashlib.sha256(
        raw_data
    ).hexdigest()

    assert row["size_bytes"] == len(
        raw_data
    )


def test_multiple_evidence_items_are_accepted(
    client: TestClient,
    test_config,
    monkeypatch,
):
    """
    One EvidenceBatch may contain multiple EvidenceEnvelope objects.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    first = make_envelope(
        evidence_id="auditd:100",
        raw_data=b"first audit event",
        sequence_start=100,
        sequence_end=100,
    )

    second = make_envelope(
        evidence_id="auditd:101",
        raw_data=b"second audit event",
        sequence_start=101,
        sequence_end=101,
    )

    third = make_envelope(
        evidence_id="auditd:102",
        raw_data=b"third audit event",
        sequence_start=102,
        sequence_end=102,
    )

    batch = make_batch(
        first,
        second,
        third,
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["received"] == 3
    assert body["stored"] == 3

    connection = app_module.get_connection(
        test_config
    )

    try:
        rows = connection.execute(
            """
            SELECT evidence_id
            FROM evidence_records
            ORDER BY evidence_id
            """
        ).fetchall()

    finally:
        connection.close()

    evidence_ids = {
        row["evidence_id"]
        for row in rows
    }

    assert evidence_ids == {
        "auditd:100",
        "auditd:101",
        "auditd:102",
    }


def test_unattributed_host_evidence_is_accepted(
    client: TestClient,
    test_config,
    monkeypatch,
):
    """
    Host audit evidence may legitimately have no tenant or instance
    attribution.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    raw_data = b"unattributed host audit event"

    envelope = make_envelope(
        evidence_id="auditd:999",
        raw_data=raw_data,
        tenant_id=None,
        instance_name=None,
    )

    batch = make_batch(
        envelope
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 200

    connection = app_module.get_connection(
        test_config
    )

    try:
        row = connection.execute(
            """
            SELECT *
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (
                envelope.evidence_id,
            ),
        ).fetchone()

    finally:
        connection.close()

    assert row is not None

    assert row["tenant_id"] is None
    assert row["project_id"] is None
    assert row["instance_name"] is None

    assert row["scope"] == "incus-host-01"
    assert row["attribution_method"] == (
        "unattributed"
    )


def test_invalid_base64_is_rejected(
    client: TestClient,
    monkeypatch,
):
    """
    Central must reject malformed Base64 before persistence.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    envelope = make_envelope()

    invalid = envelope.model_copy(
        update={
            "raw_data_b64": "%%%INVALID_BASE64%%%"
        }
    )

    batch = make_batch(
        invalid
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 400

    body = response.json()

    assert "Base64" in body["detail"]


def test_sha256_mismatch_is_rejected(
    client: TestClient,
    monkeypatch,
):
    """
    Central must reject evidence whose SHA-256 does not match
    the decoded raw bytes.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    envelope = make_envelope()

    invalid = envelope.model_copy(
        update={
            "sha256": "0" * 64
        }
    )

    batch = make_batch(
        invalid
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 400

    body = response.json()

    assert "SHA-256" in body["detail"]


def test_size_mismatch_is_rejected(
    client: TestClient,
    monkeypatch,
):
    """
    Central must reject evidence whose declared size differs
    from the decoded raw evidence.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    envelope = make_envelope()

    invalid = envelope.model_copy(
        update={
            "size_bytes": (
                envelope.size_bytes + 10
            )
        }
    )

    batch = make_batch(
        invalid
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 400

    body = response.json()

    assert "Size mismatch" in body["detail"]


def test_duplicate_evidence_is_idempotent(
    client: TestClient,
    test_config,
    monkeypatch,
):
    """
    Sending the same evidence twice must not create duplicate
    evidence records.
    """

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        lambda api_key, config: None,
    )

    envelope = make_envelope(
        evidence_id="auditd:500",
        raw_data=b"idempotent evidence",
    )

    batch = make_batch(
        envelope
    )

    first_response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    second_response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    assert first_response.json()["stored"] == 1
    assert second_response.json()["stored"] == 1

    connection = app_module.get_connection(
        test_config
    )

    try:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (
                envelope.evidence_id,
            ),
        ).fetchone()[0]

    finally:
        connection.close()

    assert count == 1


def test_api_key_verification_is_called(
    client: TestClient,
    monkeypatch,
):
    """
    Verify that the new endpoint still goes through the central
    authentication boundary.
    """

    calls = []

    def fake_verify(
        api_key,
        config,
    ):
        calls.append(
            {
                "api_key": api_key,
                "config": config,
            }
        )

    monkeypatch.setattr(
        app_module,
        "verify_api_key",
        fake_verify,
    )

    envelope = make_envelope()

    batch = make_batch(
        envelope
    )

    response = client.post(
        "/api/v1/evidence/batches",
        json=batch.model_dump(
            mode="json"
        ),
        headers={
            "X-API-Key": "test-api-key"
        },
    )

    assert response.status_code == 200

    assert len(calls) == 1

    assert calls[0]["api_key"] == (
        "test-api-key"
    )