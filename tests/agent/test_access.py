from evidenceAgent.evidenceAgent.collectors.access import AccessCollector
from evidenceAgent.evidenceAgent.models import (
    EvidenceType,
    EventType,
)
from evidenceAgent.evidenceAgent.state import AgentState


def make_collector(access_log, state_dir):
    state = AgentState(state_dir)

    return AccessCollector(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        path=str(access_log),
        state=state,
    )


def test_get_maps_to_resource_read(
    access_log,
    state_dir,
):
    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"GET /api/users HTTP/1.1" 200 123\n',
        encoding="utf-8",
    )

    collector = make_collector(
        access_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 1

    event = events[0]

    assert event.evidence_type == EvidenceType.TRACE
    assert event.event_type == EventType.RESOURCE_READ
    assert event.resource == "/api/users"
    assert event.details["method"] == "GET"
    assert event.details["status"] == 200


def test_post_maps_to_resource_create(
    access_log,
    state_dir,
):
    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"POST /api/users HTTP/1.1" 201 50\n',
        encoding="utf-8",
    )

    collector = make_collector(
        access_log,
        state_dir,
    )

    events = collector.collect()

    assert events[0].event_type == (
        EventType.RESOURCE_CREATE
    )


def test_put_maps_to_resource_update(
    access_log,
    state_dir,
):
    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"PUT /api/users/42 HTTP/1.1" 200 50\n',
        encoding="utf-8",
    )

    collector = make_collector(
        access_log,
        state_dir,
    )

    events = collector.collect()

    assert events[0].event_type == (
        EventType.RESOURCE_UPDATE
    )


def test_delete_maps_to_resource_delete(
    access_log,
    state_dir,
):
    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"DELETE /api/users/42 HTTP/1.1" 204 0\n',
        encoding="utf-8",
    )

    collector = make_collector(
        access_log,
        state_dir,
    )

    events = collector.collect()

    assert events[0].event_type == (
        EventType.RESOURCE_DELETE
    )


def test_multiple_access_events(
    access_log,
    state_dir,
):
    access_log.write_text(
        "\n".join(
            [
                '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
                '"GET / HTTP/1.1" 200 100',

                '10.0.0.2 - - [31/Aug/2026:14:00:01 +0200] '
                '"POST /users HTTP/1.1" 201 50',

                '10.0.0.3 - - [31/Aug/2026:14:00:02 +0200] '
                '"DELETE /users/1 HTTP/1.1" 204 0',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    collector = make_collector(
        access_log,
        state_dir,
    )

    events = collector.collect()

    assert len(events) == 3
    assert events[0].sequence == 1
    assert events[1].sequence == 2
    assert events[2].sequence == 3


def test_incremental_access_collection(
    access_log,
    state_dir,
):
    collector = make_collector(
        access_log,
        state_dir,
    )

    access_log.write_text(
        '10.0.0.1 - - [31/Aug/2026:14:00:00 +0200] '
        '"GET /first HTTP/1.1" 200 10\n',
        encoding="utf-8",
    )

    first = collector.collect()

    assert len(first) == 1

    access_log.open("a", encoding="utf-8").write(
        '10.0.0.1 - - [31/Aug/2026:14:00:01 +0200] '
        '"GET /second HTTP/1.1" 200 10\n'
    )

    second = collector.collect()

    assert len(second) == 1
    assert second[0].resource == "/second"