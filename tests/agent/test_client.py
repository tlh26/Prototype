from __future__ import annotations

import base64
from unittest.mock import Mock, patch

import pytest

from evidenceAgent.evidenceAgent.client import (
    CentralEvidenceClient,
)
from evidenceAgent.evidenceAgent.models import (
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


@patch(
    "evidenceAgent.evidenceAgent.client.requests.post"
)
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
        "http://127.0.0.1:9443/"
        "api/v1/evidence/events"
    )

    assert kwargs["headers"]["X-API-Key"] == "test-key"

    assert kwargs["headers"]["Content-Type"] == (
        "application/json"
    )

    assert kwargs["timeout"] == 10

    assert kwargs["json"]["raw_data"] == (
        base64.b64encode(b"hello\n").decode("ascii")
    )

    response.raise_for_status.assert_called_once()


@patch(
    "evidenceAgent.evidenceAgent.client.requests.post"
)
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

    with pytest.raises(RuntimeError, match="server error"):
        client.submit(make_event())

    response.raise_for_status.assert_called_once()


def test_submit_batch_posts_to_batch_endpoint(
    sample_batch,
):
    client = CentralEvidenceClient(
        base_url="http://central:9443",
        api_key="test-api-key",
    )

    response = Mock()
    response.raise_for_status.return_value = None

    with patch(
        "evidenceAgent.evidenceAgent.client.requests.post",
        return_value=response,
    ) as post:
        client.submit_batch(sample_batch)

    post.assert_called_once()

    args, kwargs = post.call_args

    assert args[0] == (
        "http://central:9443/"
        "api/v1/evidence/batches"
    )

    assert kwargs["headers"]["X-API-Key"] == (
        "test-api-key"
    )

    assert kwargs["headers"]["Content-Type"] == (
        "application/json"
    )

    assert kwargs["timeout"] == 10

    assert kwargs["json"]["agent_id"] == (
        sample_batch.agent_id
    )

    assert len(kwargs["json"]["evidence"]) == (
        len(sample_batch.evidence)
    )

    response.raise_for_status.assert_called_once()


def test_submit_batch_does_not_double_encode_raw_data(
    sample_batch,
):
    client = CentralEvidenceClient(
        base_url="http://central:9443",
        api_key="test-api-key",
    )

    response = Mock()
    response.raise_for_status.return_value = None

    with patch(
        "evidenceAgent.evidenceAgent.client.requests.post",
        return_value=response,
    ) as post:
        client.submit_batch(sample_batch)

    payload = post.call_args.kwargs["json"]

    for envelope in sample_batch.evidence:
        persisted = next(
            item
            for item in payload["evidence"]
            if item["evidence_id"]
            == envelope.evidence_id
        )

        assert persisted["raw_data_b64"] == (
            envelope.raw_data_b64
        )


def test_submit_batch_preserves_envelope_metadata(
    sample_batch,
):
    client = CentralEvidenceClient(
        base_url="http://central:9443",
        api_key="test-api-key",
    )

    response = Mock()
    response.raise_for_status.return_value = None

    with patch(
        "evidenceAgent.evidenceAgent.client.requests.post",
        return_value=response,
    ) as post:
        client.submit_batch(sample_batch)

    payload = post.call_args.kwargs["json"]
    envelope = payload["evidence"][0]
    original = sample_batch.evidence[0]

    assert envelope["evidence_id"] == (
        original.evidence_id
    )
    assert envelope["tenant_id"] == (
        original.tenant_id
    )
    assert envelope["instance_name"] == (
        original.instance_name
    )
    assert envelope["sha256"] == (
        original.sha256
    )
    assert envelope["size_bytes"] == (
        original.size_bytes
    )
    assert envelope["sequence_start"] == (
        original.sequence_start
    )
    assert envelope["sequence_end"] == (
        original.sequence_end
    )