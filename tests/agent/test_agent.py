from unittest.mock import Mock

from agent.agent import EvidenceAgent


def test_agent_initializes(agent_config):
    agent = EvidenceAgent(agent_config)

    assert agent.config == agent_config
    assert agent.state.get_sequence() == 0


def test_agent_creates_state_directory(
    agent_config,
):
    agent = EvidenceAgent(agent_config)

    assert agent.state.directory.exists()


def test_agent_collect_once_with_no_evidence(
    agent_config,
):
    agent = EvidenceAgent(agent_config)

    agent.client.submit = Mock()

    agent.collect_once()

    agent.client.submit.assert_not_called()


def test_agent_processes_authentication_event(
    agent_config,
    auth_log,
):
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[123]: "
            "Accepted password for appuser from "
            "10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    agent = EvidenceAgent(agent_config)

    agent.client.submit = Mock()

    agent.collect_once()

    agent.client.submit.assert_called_once()

    event = agent.client.submit.call_args.args[0]

    assert event.tenant_id == "tenant-b"
    assert event.instance_name == "web-b"
    assert event.agent_id == "agent-web-b"


def test_successful_submission_removes_spool(
    agent_config,
    auth_log,
):
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[123]: "
            "Accepted password for appuser from "
            "10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    agent = EvidenceAgent(agent_config)

    agent.client.submit = Mock()

    agent.collect_once()

    assert agent.spool.pending() == []


def test_failed_submission_keeps_spool(
    agent_config,
    auth_log,
):
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[123]: "
            "Accepted password for appuser from "
            "10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    agent = EvidenceAgent(agent_config)

    agent.client.submit = Mock(
        side_effect=ConnectionError(
            "central unavailable"
        )
    )

    agent.collect_once()

    pending = agent.spool.pending()

    assert len(pending) == 1


def test_multiple_collectors_share_sequence(
    agent_config,
    auth_log,
    access_log,
    watched_directory,
):
    """
    Verify that authentication, access, and file collectors
    use the same monotonically increasing agent sequence.

    The file collector establishes an initial filesystem baseline
    during the first collection. Therefore, the file must be
    created after that baseline has been established.
    """

    # ------------------------------------------------------------------
    # Prepare authentication evidence.
    # ------------------------------------------------------------------
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[123]: "
            "Accepted password for appuser from "
            "10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # Prepare access evidence.
    # ------------------------------------------------------------------
    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"GET /api/users HTTP/1.1" 200 10\n',
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # Create the agent.
    #
    # Do NOT create the watched file yet. The file collector needs
    # to establish its initial filesystem baseline first.
    # ------------------------------------------------------------------
    agent = EvidenceAgent(agent_config)

    submitted = []

    agent.client.submit = lambda event: submitted.append(event)

    # ------------------------------------------------------------------
    # First collection.
    #
    # Expected:
    #   1. Authentication event
    #   2. Access event
    #
    # The file collector establishes its baseline here and therefore
    # should not report a file event yet.
    # ------------------------------------------------------------------
    agent.collect_once()

    assert len(submitted) == 2

    # ------------------------------------------------------------------
    # Generate new filesystem evidence AFTER the baseline exists.
    # ------------------------------------------------------------------
    watched_directory.joinpath(
        "evidence.txt"
    ).write_text(
        "test",
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # Second collection.
    #
    # Expected:
    #   3. File activity event
    # ------------------------------------------------------------------
    agent.collect_once()

    assert len(submitted) == 3

    # ------------------------------------------------------------------
    # Verify that all collectors share one sequence.
    # ------------------------------------------------------------------
    sequences = [
        event.sequence
        for event in submitted
    ]

    assert sequences == [1, 2, 3]

    # Every event must have a unique sequence number.
    assert len(sequences) == len(set(sequences))

    # Sequence numbers must be monotonically increasing.
    assert sequences == sorted(sequences)

    # ------------------------------------------------------------------
    # Verify that the three expected evidence types were collected.
    # ------------------------------------------------------------------
    evidence_types = [
        event.evidence_type
        for event in submitted
    ]

    assert evidence_types[0].value == "authentication"
    assert evidence_types[1].value == "trace"
    assert evidence_types[2].value == "file"