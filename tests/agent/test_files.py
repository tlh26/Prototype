from agent.collectors.files import FileCollector
from agent.models import EventType
from agent.state import AgentState


def make_collector(
    watched_directory,
    state_dir,
):
    state = AgentState(state_dir)

    return FileCollector(
        tenant_id="tenant-b",
        instance_name="web-b",
        agent_id="agent-web-b",
        paths=(str(watched_directory),),
        state=state,
    )


def test_new_file_is_detected(
    watched_directory,
    state_dir,
):
    collector = make_collector(
        watched_directory,
        state_dir,
    )

    watched_directory.joinpath(
        "new.txt"
    ).write_text(
        "hello",
        encoding="utf-8",
    )

    events = collector.collect()

    assert len(events) == 1

    event = events[0]

    assert event.event_type == EventType.FILE_CREATE
    assert event.resource.endswith("new.txt")


def test_deleted_file_is_detected(
    watched_directory,
    state_dir,
):
    file_path = watched_directory / "existing.txt"

    file_path.write_text(
        "hello",
        encoding="utf-8",
    )

    collector = make_collector(
        watched_directory,
        state_dir,
    )

    file_path.unlink()

    events = collector.collect()

    assert len(events) == 1
    assert events[0].event_type == EventType.FILE_DELETE


def test_existing_files_are_not_reported_as_new(
    watched_directory,
    state_dir,
):
    (watched_directory / "existing.txt").write_text(
        "hello",
        encoding="utf-8",
    )

    collector = make_collector(
        watched_directory,
        state_dir,
    )

    events = collector.collect()

    assert events == []


def test_multiple_new_files_are_detected(
    watched_directory,
    state_dir,
):
    collector = make_collector(
        watched_directory,
        state_dir,
    )

    for name in ["a.txt", "b.txt", "c.txt"]:
        (watched_directory / name).write_text(
            name,
            encoding="utf-8",
        )

    events = collector.collect()

    assert len(events) == 3

    resources = {
        event.resource
        for event in events
    }

    assert any(
        resource.endswith("a.txt")
        for resource in resources
    )

    assert any(
        resource.endswith("b.txt")
        for resource in resources
    )

    assert any(
        resource.endswith("c.txt")
        for resource in resources
    )