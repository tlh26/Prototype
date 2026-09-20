from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone

import pytest

from central.genericRepo import GenericEvidenceRepository
from evidence.evidence import EvidenceRecord
from collections.abc import Generator


@pytest.fixture
def connection() -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,

            tenant_id TEXT,
            tenant_hash TEXT,

            project_id TEXT,
            instance_name TEXT,

            scope TEXT,

            source TEXT NOT NULL,
            source_path TEXT NOT NULL,

            acquisition_layer TEXT NOT NULL,
            acquired_from TEXT NOT NULL,
            attribution_method TEXT NOT NULL,

            collected_at TEXT NOT NULL,

            raw_data BLOB NOT NULL,

            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,

            sequence_start INTEGER,
            sequence_end INTEGER,

            capture_id TEXT,

            record_sha256 TEXT
        )
        """
    )

    yield connection

    connection.close()


@pytest.fixture
def repository(
    connection: sqlite3.Connection,
) -> GenericEvidenceRepository:
    return GenericEvidenceRepository(connection)


def make_evidence(
    *,
    evidence_id: str = "auditd:100",
    tenant_id: str | None = "tenant-b",
    instance_name: str | None = "web-b",
    raw_data: bytes = b"type=SYSCALL msg=audit(123): test",
) -> EvidenceRecord:

    sha256 = hashlib.sha256(raw_data).hexdigest()

    return EvidenceRecord(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        tenant_hash=None,
        project_id=tenant_id,
        instance_name=instance_name,
        scope=(
            f"{tenant_id}/{instance_name}"
            if tenant_id and instance_name
            else "incus-host-01"
        ),
        source="auditd",
        source_path="/var/log/audit/audit.log",
        acquisition_layer="host",
        acquired_from="incus-host-01",
        attribution_method=(
            "incus_metadata"
            if tenant_id
            else "unattributed"
        ),
        collected_at=datetime.now(timezone.utc),
        raw_data=raw_data,
        sha256=sha256,
        size_bytes=len(raw_data),
        sequence_start=100,
        sequence_end=100,
        capture_id="capture-001",
    )


def test_save_and_get_evidence(
    repository: GenericEvidenceRepository,
):
    evidence = make_evidence()

    repository.save(evidence)

    result = repository.get(
        evidence.evidence_id
    )

    assert result is not None

    assert result["evidence_id"] == evidence.evidence_id
    assert result["tenant_id"] == "tenant-b"
    assert result["project_id"] == "tenant-b"
    assert result["instance_name"] == "web-b"
    assert result["source"] == "auditd"

    assert result["raw_data"] == evidence.raw_data
    assert result["sha256"] == evidence.sha256
    assert result["size_bytes"] == len(evidence.raw_data)


def test_saved_raw_bytes_are_identical(
    repository: GenericEvidenceRepository,
):
    raw_data = (
        b"\x00\x01\x02"
        b" forensic evidence "
        b"\xff\xfe"
    )

    evidence = make_evidence(
        raw_data=raw_data
    )

    repository.save(evidence)

    result = repository.get(
        evidence.evidence_id
    )

    assert result is not None
    assert result["raw_data"] == raw_data


def test_sha256_is_verified_before_storage(
    repository: GenericEvidenceRepository,
):
    evidence = make_evidence()

    invalid = evidence.model_copy(
        update={
            "sha256": "0" * 64,
        }
    )

    with pytest.raises(ValueError):
        repository.save(invalid)

    assert repository.get(
        evidence.evidence_id
    ) is None


def test_size_is_verified_before_storage(
    repository: GenericEvidenceRepository,
):
    evidence = make_evidence()

    invalid = evidence.model_copy(
        update={
            "size_bytes": evidence.size_bytes + 1,
        }
    )

    with pytest.raises(ValueError):
        repository.save(invalid)

    assert repository.get(
        evidence.evidence_id
    ) is None


def test_duplicate_identical_evidence_is_idempotent(
    repository: GenericEvidenceRepository,
):
    evidence = make_evidence()

    repository.save(evidence)
    repository.save(evidence)

    result = repository.get(
        evidence.evidence_id
    )

    assert result is not None
    assert result["sha256"] == evidence.sha256


def test_same_id_with_different_hash_is_rejected(
    repository: GenericEvidenceRepository,
):
    first = make_evidence(
        evidence_id="auditd:100",
        raw_data=b"original evidence",
    )

    second = make_evidence(
        evidence_id="auditd:100",
        raw_data=b"different evidence",
    )

    repository.save(first)

    with pytest.raises(ValueError):
        repository.save(second)


def test_list_filters_by_tenant(
    repository: GenericEvidenceRepository,
):
    repository.save(
        make_evidence(
            evidence_id="event-tenant-b",
            tenant_id="tenant-b",
            instance_name="web-b",
        )
    )

    repository.save(
        make_evidence(
            evidence_id="event-tenant-a",
            tenant_id="tenant-a",
            instance_name="web-a",
        )
    )

    results = repository.list(
        tenant_id="tenant-b"
    )

    assert len(results) == 1
    assert results[0]["tenant_id"] == "tenant-b"


def test_list_filters_by_instance(
    repository: GenericEvidenceRepository,
):
    repository.save(
        make_evidence(
            evidence_id="event-web-b",
            tenant_id="tenant-b",
            instance_name="web-b",
        )
    )

    repository.save(
        make_evidence(
            evidence_id="event-db-b",
            tenant_id="tenant-b",
            instance_name="db-b",
        )
    )

    results = repository.list(
        instance_name="web-b"
    )

    assert len(results) == 1
    assert results[0]["instance_name"] == "web-b"


def test_unattributed_host_evidence_can_be_stored(
    repository: GenericEvidenceRepository,
):
    evidence = make_evidence(
        evidence_id="auditd:999",
        tenant_id=None,
        instance_name=None,
    )

    repository.save(evidence)

    result = repository.get(
        evidence.evidence_id
    )

    assert result is not None
    assert result["tenant_id"] is None
    assert result["instance_name"] is None
    assert result["scope"] == "incus-host-01"
    assert result["attribution_method"] == "unattributed"