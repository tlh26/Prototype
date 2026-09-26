import json

import pytest

from evidenceAgent.evidenceAgent.state import AgentState


def test_state_initializes(state_dir):
    state = AgentState(state_dir)

    assert state.get_sequence() == 0


def test_state_directory_is_created(state_dir):
    state = AgentState(state_dir)

    assert state.directory.exists()
    assert state.path.exists()


def test_sequence_can_be_updated(state_dir):
    state = AgentState(state_dir)

    state.set_sequence(1)

    assert state.get_sequence() == 1

    state.set_sequence(2)

    assert state.get_sequence() == 2


def test_sequence_cannot_move_backwards(state_dir):
    state = AgentState(state_dir)

    state.set_sequence(10)

    with pytest.raises(ValueError):
        state.set_sequence(9)

    assert state.get_sequence() == 10


def test_state_survives_restart(state_dir):
    state = AgentState(state_dir)

    state.set_sequence(42)

    restarted = AgentState(state_dir)

    assert restarted.get_sequence() == 42


def test_state_file_contains_sequence(state_dir):
    state = AgentState(state_dir)

    state.set_sequence(5)

    data = json.loads(state.path.read_text(encoding="utf-8"))

    assert data["sequence"] == 5
