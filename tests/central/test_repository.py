from datetime import datetime, timezone

from central.database import (
    get_connection,
    initialise_database,
)
from central.repository import EvidenceRepository


def test_database_initialises(tmp_path):
    config = type(
        "Config",
        (),
        {"database_path": str(tmp_path / "evidence.db")},
    )()

    initialise_database(config)

    assert (tmp_path / "evidence.db").exists()


def test_repository_get_missing_event(
    tmp_path,
):
    config = type(
        "Config",
        (),
        {"database_path": str(tmp_path / "evidence.db")},
    )()

    initialise_database(config)

    connection = get_connection(config)

    try:
        repository = EvidenceRepository(connection)

        assert repository.get("missing-event") is None

    finally:
        connection.close()
