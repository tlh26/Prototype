from __future__ import annotations

import base64
import hashlib

import pytest

from evidenceAgent.evidenceAgent.config import AgentConfig
from evidenceAgent.evidenceAgent.transportModels import (
    EvidenceBatch,
    EvidenceEnvelope,
)


@pytest.fixture
def state_dir(tmp_path):
    return str(tmp_path / "agent-state")


@pytest.fixture
def auth_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("", encoding="utf-8")
    return path


@pytest.fixture
def access_log(tmp_path):
    path = tmp_path / "access.log"
    path.write_text("", encoding="utf-8")
    return path


@pytest.fixture
def watched_directory(tmp_path):
    path = tmp_path / "watched"
    path.mkdir()
    return path


@pytest.fixture
def agent_config(
    state_dir,
    auth_log,
    access_log,
    watched_directory,
):
    return AgentConfig(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        central_url="http://127.0.0.1:9443",
        api_key="test-key",
        auth_log=str(auth_log),
        access_log=str(access_log),
        watched_directory=str(watched_directory),
        state_directory=state_dir,
        spool_directory=f"{state_dir}/spool",
        interval=0.01,
    )


@pytest.fixture
def sample_envelope():
    raw_data = b"test evidence\n"

    return EvidenceEnvelope(
        evidence_id="evidence-001",
        tenant_id="tenant-b",
        tenant_hash=None,
        project_id="tenant-b",
        instance_name="web-b",
        scope="instance",
        source="filesystem",
        source_path="/tmp/test.txt",
        acquisition_layer="agent",
        acquired_from="web-b",
        attribution_method="instance-agent",
        collected_at=__import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ),
        raw_data_b64=base64.b64encode(raw_data).decode("ascii"),
        sha256=hashlib.sha256(raw_data).hexdigest(),
        size_bytes=len(raw_data),
        sequence_start=1,
        sequence_end=1,
        capture_id="capture-001",
    )


@pytest.fixture
def sample_batch(sample_envelope):
    return EvidenceBatch(
        agent_id="agent-host-smoke-test",
        evidence=(sample_envelope,),
    )
