from __future__ import annotations

import pytest

from agent.config import AgentConfig


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
def agent_config(state_dir, auth_log, access_log, watched_directory):
    return AgentConfig(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        central_url="http://127.0.0.1:9443",
        api_key="test-key",
        state_dir=state_dir,
        poll_interval=0.01,
        auth_log=str(auth_log),
        access_log=str(access_log),
        watch_paths=(str(watched_directory),),
    )