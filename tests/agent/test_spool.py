from __future__ import annotations

import base64
import json

from evidenceAgent.evidenceAgent.spool import (
    EvidenceSpool,
)


def test_spool_creates_directory(tmp_path):
    spool_path = tmp_path / "spool"

    EvidenceSpool(str(spool_path))

    assert spool_path.exists()
    assert spool_path.is_dir()


def test_batch_can_be_stored(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(sample_batch)

    assert path.exists()
    assert path.suffix == ".json"


def test_pending_returns_stored_batches(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    spool.store(sample_batch)

    pending = spool.pending()

    assert len(pending) == 1


def test_pending_is_sorted_by_filename(
    tmp_path,
    sample_envelope,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    from evidenceAgent.evidenceAgent.transportModels import (
        EvidenceBatch,
    )

    batch_2 = EvidenceBatch(
        agent_id="agent-2",
        evidence=(
            sample_envelope.model_copy(
                update={
                    "evidence_id": "evidence-2",
                    "sequence_start": 2,
                    "sequence_end": 2,
                }
            ),
        ),
    )

    batch_1 = EvidenceBatch(
        agent_id="agent-1",
        evidence=(
            sample_envelope.model_copy(
                update={
                    "evidence_id": "evidence-1",
                    "sequence_start": 1,
                    "sequence_end": 1,
                }
            ),
        ),
    )

    spool.store(batch_2)
    spool.store(batch_1)

    pending = spool.pending()

    assert len(pending) == 2

    assert pending[0].name.startswith(
        "00000000000000000001"
    )

    assert pending[1].name.startswith(
        "00000000000000000002"
    )


def test_spooled_batch_contains_raw_data_b64(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(sample_batch)

    payload = json.loads(
        path.read_text(encoding="utf-8")
    )

    envelope = sample_batch.evidence[0]

    assert payload["evidence"][0]["raw_data_b64"] == (
        envelope.raw_data_b64
    )

    decoded = base64.b64decode(
        payload["evidence"][0]["raw_data_b64"]
    )

    assert decoded == b"test evidence\n"


def test_spooled_batch_can_be_loaded(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(sample_batch)

    loaded = spool.load(path)

    assert loaded == sample_batch


def test_spool_batch_can_be_removed(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(sample_batch)

    assert path.exists()

    spool.remove(path)

    assert not path.exists()


def test_remove_missing_spool_file_is_safe(
    tmp_path,
    sample_batch,
):
    spool = EvidenceSpool(
        str(tmp_path / "spool")
    )

    path = spool.store(sample_batch)

    spool.remove(path)

    # remove() uses missing_ok=True
    spool.remove(path)

    assert not path.exists()