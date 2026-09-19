from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from evidenceAgent.evidenceAgent.spool import (
    EvidenceSpool,
)
from evidenceAgent.evidenceAgent.transportModels import (
    EvidenceBatch,
    EvidenceEnvelope,
)


def make_batch() -> EvidenceBatch:
    raw_data = (
        b"type=SYSCALL "
        b"msg=audit(123.456:100): "
        b"arch=c000003e"
    )

    envelope = EvidenceEnvelope(
        evidence_id=(
            "auditd:100:"
            + hashlib.sha256(
                raw_data
            ).hexdigest()
        ),

        tenant_id="tenant-b",
        tenant_hash=None,

        project_id="tenant-b",
        instance_name="web-b",

        scope="tenant-b/web-b",

        source="auditd",
        source_path="/var/log/audit/audit.log",

        acquisition_layer="host",
        acquired_from="incus-host-01",
        attribution_method="incus_metadata",

        collected_at=datetime.now(
            timezone.utc
        ),

        raw_data_b64=base64.b64encode(
            raw_data
        ).decode("ascii"),

        sha256=hashlib.sha256(
            raw_data
        ).hexdigest(),

        size_bytes=len(raw_data),

        sequence_start=100,
        sequence_end=100,

        capture_id="capture-001",
    )

    return EvidenceBatch(
        agent_id="agent-host-incus-01",
        evidence=(envelope,),
    )


def test_batch_can_be_stored_in_spool(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    batch = make_batch()

    path = spool.store(
        batch
    )

    assert path.exists()

    assert path.parent == tmp_path


def test_spooled_batch_can_be_loaded(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    original = make_batch()

    path = spool.store(
        original
    )

    loaded = spool.load(
        path
    )

    assert loaded.agent_id == (
        original.agent_id
    )

    assert len(
        loaded.evidence
    ) == 1

    original_envelope = (
        original.evidence[0]
    )

    loaded_envelope = (
        loaded.evidence[0]
    )

    assert (
        loaded_envelope.evidence_id
        == original_envelope.evidence_id
    )

    assert (
        loaded_envelope.raw_data_b64
        == original_envelope.raw_data_b64
    )

    assert (
        loaded_envelope.sha256
        == original_envelope.sha256
    )

    assert (
        loaded_envelope.size_bytes
        == original_envelope.size_bytes
    )


def test_base64_round_trip_preserves_raw_bytes(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    batch = make_batch()

    path = spool.store(
        batch
    )

    loaded = spool.load(
        path
    )

    envelope = loaded.evidence[0]

    raw_data = base64.b64decode(
        envelope.raw_data_b64,
        validate=True,
    )

    assert raw_data == (
        b"type=SYSCALL "
        b"msg=audit(123.456:100): "
        b"arch=c000003e"
    )

    assert hashlib.sha256(
        raw_data
    ).hexdigest() == envelope.sha256


def test_pending_returns_spooled_batches(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    batch = make_batch()

    path = spool.store(
        batch
    )

    pending = spool.pending()

    assert path in pending


def test_remove_deletes_successfully_sent_batch(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    batch = make_batch()

    path = spool.store(
        batch
    )

    assert path.exists()

    spool.remove(
        path
    )

    assert not path.exists()


def test_multiple_batches_are_kept(
    tmp_path,
):
    spool = EvidenceSpool(
        str(tmp_path)
    )

    first = make_batch()

    second = first.model_copy(
        update={
            "evidence": (
                first.evidence[0].model_copy(
                    update={
                        "evidence_id": "auditd:101"
                    }
                ),
            )
        }
    )

    first_path = spool.store(first)
    second_path = spool.store(second)

    pending = spool.pending()

    assert first_path in pending
    assert second_path in pending