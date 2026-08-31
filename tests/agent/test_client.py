from unittest.mock import Mock, patch

import pytest

from agent.client import CentralEvidenceClient
from agent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


def make_event():
    return EvidenceEvent.now(
        event_id="event-001",
        tenant_id="tenant-b",
        instance_name="web-b",
        evidence_type=EvidenceType.FILE,
        event_type=EventType.FILE_CREATE,
        sequence=1,
        agent_id="agent-web-b",
        source="filesystem",
        raw_data=b"hello\n",
    )


@patch("agent.client.requests.post")
def test_client_submits_event(mock_post):
    response = Mock()
    response.raise_for_status.return_value = None

    mock_post.return_value = response

    client = CentralEvidenceClient(
        base_url="http://127.0.0.1:9443",
        api_key="test-key",
    )

    client.submit(make_event())

    mock_post.assert_called_once()

    args, kwargs = mock_post.call_args

    assert args[0] == (
        "http://127.0.0.1:9443/api/v1/evidence"
    )

    assert kwargs["headers"]["Authorization"] == (
        "Bearer test-key"
    )

    assert kwargs["timeout"] == 10


@patch("agent.client.requests.post")
def test_client_propagates_http_error(mock_post):
    response = Mock()

    response.raise_for_status.side_effect = (
        RuntimeError("server error")
    )

    mock_post.return_value = response

    client = CentralEvidenceClient(
        base_url="http://127.0.0.1:9443",
        api_key="test-key",
    )

    with pytest.raises(RuntimeError):
        client.submit(make_event())