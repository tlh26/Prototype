from agent.collectors.authentication import (
    AuthenticationCollector,
)
from agent.models import (
    EvidenceType,
    EventType,
)
from agent.state import AgentState


def create_collector(
    auth_log,
    state_dir,
):
    state = AgentState(state_dir)

    return AuthenticationCollector(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        path=str(auth_log),
        state=state,
    )


def test_successful_login_is_collected(
    auth_log,
    state_dir,
):
    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[123]: "
            "Accepted password for appuser from 10.0.0.5 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    collector = create_collector(
        auth_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 1

    event = events[0]

    assert event.tenant_id == "tenant-b"
    assert event.instance_name == "web-b"

    assert event.evidence_type == (
        EvidenceType.AUTHENTICATION
    )

    assert event.event_type == (
        EventType.LOGIN_SUCCESS
    )

    assert event.actor == "appuser"


def test_failed_login_is_collected(
    auth_log,
    state_dir,
):
    auth_log.write_text(
        (
            "Aug 31 14:01:00 web-b sshd[123]: "
            "Failed password for appuser from 10.0.0.8 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    collector = create_collector(
        auth_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 1
    assert events[0].event_type == (
        EventType.LOGIN_FAILURE
    )


def test_session_opened_is_collected(
    auth_log,
    state_dir,
):
    auth_log.write_text(
        (
            "Aug 31 14:02:00 web-b sudo: "
            "pam_unix(sudo:session): session opened for user root\n"
        ),
        encoding="utf-8",
    )

    collector = create_collector(
        auth_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 1
    assert events[0].event_type == (
        EventType.SESSION_CREATED
    )


def test_session_closed_is_collected(
    auth_log,
    state_dir,
):
    auth_log.write_text(
        (
            "Aug 31 14:03:00 web-b sudo: "
            "pam_unix(sudo:session): session closed for user root\n"
        ),
        encoding="utf-8",
    )

    collector = create_collector(
        auth_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 1
    assert events[0].event_type == (
        EventType.SESSION_TERMINATED
    )


def test_incremental_collection(
    auth_log,
    state_dir,
):
    collector = create_collector(
        auth_log,
        state_dir,
    )

    auth_log.write_text(
        (
            "Aug 31 14:00:00 web-b sshd[1]: "
            "Accepted password for user1 from 10.0.0.1 port 1234 ssh2\n"
        ),
        encoding="utf-8",
    )

    first = collector.collect()

    assert len(first) == 1

    auth_log.open("a", encoding="utf-8").write(
        (
            "Aug 31 14:00:01 web-b sshd[2]: "
            "Accepted password for user2 from 10.0.0.2 port 1235 ssh2\n"
        )
    )

    second = collector.collect()

    assert len(second) == 1
    assert second[0].actor == "user2"


def test_missing_auth_log_returns_empty(
    tmp_path,
    state_dir,
):
    missing = tmp_path / "does-not-exist.log"

    state = AgentState(state_dir)

    collector = AuthenticationCollector(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        path=str(missing),
        state=state,
    )

    assert collector.collect() == []