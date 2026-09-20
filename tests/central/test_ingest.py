from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest

from central.ingest import (
    IngestionError,
    decode_evidence,
    envelope_to_record,
)
from evidenceAgent.evidenceAgent.transportModels import (
    EvidenceEnvelope,
)


def make_envelope(
    *,
    raw_data: bytes = b"forensic evidence",
    evidence_id: str = "auditd:100",
) -> EvidenceEnvelope:

    return EvidenceEnvelope(
        evidence_id=evidence_id,

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


def test_decode_valid_evidence():
    raw_data = (
        b"type=SYSCALL "
        b"msg=audit(123): test"
    )

    envelope = make_envelope(
        raw_data=raw_data
    )

    decoded = decode_evidence(
        envelope
    )

    assert decoded == raw_data


def test_decode_rejects_invalid_base64():
    envelope = make_envelope()

    invalid = envelope.model_copy(
        update={
            "raw_data_b64": "%%%NOT_BASE64%%%"
        }
    )

    with pytest.raises(IngestionError):
        decode_evidence(invalid)


def test_decode_rejects_size_mismatch():
    raw_data = b"test evidence"

    envelope = make_envelope(
        raw_data=raw_data
    )

    invalid = envelope.model_copy(
        update={
            "size_bytes": len(raw_data) + 1
        }
    )

    with pytest.raises(IngestionError):
        decode_evidence(invalid)


def test_decode_rejects_sha256_mismatch():
    envelope = make_envelope()

    invalid = envelope.model_copy(
        update={
            "sha256": "0" * 64
        }
    )

    with pytest.raises(IngestionError):
        decode_evidence(invalid)


def test_envelope_converts_to_evidence_record():
    raw_data = b"raw audit evidence"

    envelope = make_envelope(
        raw_data=raw_data
    )

    record = envelope_to_record(
        envelope
    )

    assert record.evidence_id == envelope.evidence_id
    assert record.tenant_id == "tenant-b"
    assert record.project_id == "tenant-b"
    assert record.instance_name == "web-b"

    assert record.raw_data == raw_data

    assert record.sha256 == hashlib.sha256(
        raw_data
    ).hexdigest()

    assert record.size_bytes == len(
        raw_data
    )

    assert record.sequence_start == 100
    assert record.sequence_end == 100
    assert record.capture_id == "capture-001"


def test_unattributed_envelope_is_supported():
    raw_data = b"host audit event"

    envelope = make_envelope(
        raw_data=raw_data
    ).model_copy(
        update={
            "tenant_id": None,
            "project_id": None,
            "instance_name": None,
            "scope": "incus-host-01",
            "attribution_method": "unattributed",
        }
    )

    record = envelope_to_record(
        envelope
    )

    assert record.tenant_id is None
    assert record.project_id is None
    assert record.instance_name is None
    assert record.scope == "incus-host-01"
    assert record.attribution_method == "unattributed"