import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from central.app import app
from central.config import CentralConfig
from central.database import initialise_database


@pytest.fixture
def central_config(tmp_path):
    return CentralConfig(
        host="127.0.0.1",
        port=9443,
        database_path=str(
            tmp_path / "evidence.db"
        ),
        api_key="test-api-key",
    )


@pytest.fixture
def client(monkeypatch, central_config):
    """
    Create a TestClient using an isolated temporary database.
    """

    monkeypatch.setattr(
        "central.app.config",
        central_config,
    )

    initialise_database(central_config)

    return TestClient(app)


@pytest.fixture
def api_key():
    return "test-api-key"


@pytest.fixture
def raw_data():
    return (
        b"Aug 31 14:00:00 web-b sshd[123]: "
        b"Accepted password for appuser\n"
    )


@pytest.fixture
def evidence_payload(raw_data):
    sha256 = hashlib.sha256(
        raw_data
    ).hexdigest()

    encoded = base64.b64encode(
        raw_data
    ).decode("ascii")

    return {
        "event_id": "event-001",
        "tenant_id": "tenant-b",
        "instance_name": "web-b",
        "evidence_type": "authentication",
        "event_type": "LOGIN_SUCCESS",
        "timestamp": "2026-08-31T14:00:00+00:00",
        "actor": "appuser",
        "uid": None,
        "resource": "10.0.0.5",
        "source": "auth.log",
        "source_path": "/var/log/auth.log",
        "details": {
            "method": "password",
            "raw_line": (
                "Aug 31 14:00:00 web-b "
                "sshd[123]: Accepted password "
                "for appuser\n"
            ),
        },
        "sequence": 1,
        "agent_id": "agent-web-b",
        "raw_data": encoded,
        "sha256": sha256,
        "created_at": "2026-08-31T14:00:01+00:00",
    }


@pytest.fixture
def auth_headers(api_key):
    return {
        "X-API-Key": api_key,
    }