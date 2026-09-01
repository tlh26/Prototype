from unittest.mock import Mock

from evidenceAgent.evidenceAgent.agent import EvidenceAgent
from evidenceAgent.evidenceAgent.models import EvidenceType

def test_end_to_end_local_agent_pipeline(
    agent_config,
    auth_log,
    access_log,
    watched_directory,
):
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[100]: "
            "Accepted password for appuser from "
            "10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"GET /api/users HTTP/1.1" 200 100\n',
        encoding="utf-8",
    )

    agent = EvidenceAgent(agent_config)

    submitted = []

    agent.client.submit = Mock(
        side_effect=lambda event: submitted.append(event)
    )

    # First collection establishes the filesystem baseline
    # and collects the existing authentication/access evidence.
    agent.collect_once()

    assert len(submitted) == 2

    # Generate a new filesystem event after baseline creation.
    watched_directory.joinpath("test.txt").write_text(
        "forensic test",
        encoding="utf-8",
    )

    # Second collection should detect the new file.
    agent.collect_once()

    assert len(submitted) == 3

    assert submitted[0].evidence_type == EvidenceType.AUTHENTICATION
    assert submitted[1].evidence_type == EvidenceType.TRACE
    assert submitted[2].evidence_type == EvidenceType.FILE

    assert submitted[0].sequence == 1
    assert submitted[1].sequence == 2
    assert submitted[2].sequence == 3