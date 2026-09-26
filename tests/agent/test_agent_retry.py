from __future__ import annotations

from unittest.mock import Mock

from evidenceAgent.evidenceAgent.hostAgent import (
    HostEvidenceAgent,
)


def make_agent(agent_config, tmp_path):
    collector = Mock()

    config = agent_config

    return HostEvidenceAgent(
        config=config,
        collector=collector,
    )


def test_failed_delivery_retains_spool(
    agent_config,
    sample_batch,
):
    agent = make_agent(
        agent_config,
        None,
    )

    agent.client = Mock()

    agent.client.submit_batch.side_effect = RuntimeError("central unavailable")

    agent.process_batch(sample_batch)

    pending = agent.spool.pending()

    assert len(pending) == 1

    assert pending[0].exists()

    stored = agent.spool.load(pending[0])

    assert stored == sample_batch

    agent.client.submit_batch.assert_called_once_with(sample_batch)


def test_successful_delivery_removes_spool(
    agent_config,
    sample_batch,
):
    agent = make_agent(
        agent_config,
        None,
    )

    agent.client = Mock()

    agent.client.submit_batch.return_value = {
        "status": "accepted",
        "received": 1,
        "stored": 1,
    }

    agent.process_batch(sample_batch)

    assert agent.spool.pending() == []

    agent.client.submit_batch.assert_called_once_with(sample_batch)


def test_retry_success_removes_spool(
    agent_config,
    sample_batch,
):
    agent = make_agent(
        agent_config,
        None,
    )

    # First simulate the original outage.
    spool_path = agent.spool.store(sample_batch)

    assert spool_path.exists()

    agent.client = Mock()

    agent.client.submit_batch.return_value = {
        "status": "accepted",
        "received": 1,
        "stored": 1,
    }

    agent.retry_spool()

    assert not spool_path.exists()
    assert agent.spool.pending() == []

    agent.client.submit_batch.assert_called_once_with(sample_batch)


def test_retry_failure_retains_spool(
    agent_config,
    sample_batch,
):
    agent = make_agent(
        agent_config,
        None,
    )

    spool_path = agent.spool.store(sample_batch)

    assert spool_path.exists()

    agent.client = Mock()

    agent.client.submit_batch.side_effect = RuntimeError("central still unavailable")

    agent.retry_spool()

    assert spool_path.exists()

    pending = agent.spool.pending()

    assert len(pending) == 1

    assert agent.spool.load(pending[0]) == sample_batch

    agent.client.submit_batch.assert_called_once_with(sample_batch)


def test_retry_multiple_batches(
    agent_config,
    sample_batch,
    sample_envelope,
):
    from evidenceAgent.evidenceAgent.transportModels import (
        EvidenceBatch,
    )

    agent = make_agent(
        agent_config,
        None,
    )

    batch_1 = sample_batch

    batch_2 = EvidenceBatch(
        agent_id="agent-host-smoke-test",
        evidence=(
            sample_envelope.model_copy(
                update={
                    "evidence_id": "evidence-002",
                    "sequence_start": 2,
                    "sequence_end": 2,
                }
            ),
        ),
    )

    agent.spool.store(batch_1)
    agent.spool.store(batch_2)

    assert len(agent.spool.pending()) == 2

    agent.client = Mock()
    agent.client.submit_batch.return_value = {
        "status": "accepted",
        "received": 1,
        "stored": 1,
    }

    agent.retry_spool()

    assert agent.spool.pending() == []

    assert agent.client.submit_batch.call_count == 2
