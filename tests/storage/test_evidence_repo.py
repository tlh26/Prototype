# tests/storage/test_evidence_repo.py

from __future__ import annotations

import hashlib

from datetime import datetime, timezone

import pytest

from acquisition.collectors.audit import AuditEvidence
from storage.evidenceRepo import SQLiteEvidenceRepository


def make_evidence(
    *,
    evidence_id: str = "evidence-001",
    tenant_id: str = "tenant-b",
    instance_name: str = "web-b",
    source: str = "audit",
    raw_data: bytes = b"audit event\n",
) -> AuditEvidence:

    sha256 = hashlib.sha256(raw_data).hexdigest()

    return AuditEvidence(
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        tenant_hash="tenant-hash-b",
        project_id="tenant-b",
        instance_name=instance_name,
        scope="instance",
        source=source,
        source_path="/var/log/audit/audit.log",
        acquisition_layer="host",
        acquired_from="incus-host",
        attribution_method="incus-instance-mapping",
        collected_at=datetime.now(timezone.utc),
        raw_data=raw_data,
        sha256=sha256,
        size_bytes=len(raw_data),
        sequence_start=100,
        sequence_end=101,
    )


def test_repository_creates_database(
    tmp_path,
):
    database = tmp_path / "evidence.db"

    repository = SQLiteEvidenceRepository(database)

    assert database.exists()

    assert repository.count_evidence() == 0


def test_save_and_get_evidence(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    evidence_id = repository.save_audit(evidence)

    assert evidence_id == (evidence.evidence_id)

    row = repository.get_evidence(evidence.evidence_id)

    assert row is not None

    assert row["evidence_id"] == (evidence.evidence_id)

    assert bytes(row["raw_data"]) == (evidence.raw_data)


def test_saved_raw_sha256_matches_payload(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    row = repository.get_evidence(evidence.evidence_id)

    expected = hashlib.sha256(evidence.raw_data).hexdigest()

    assert row["sha256"] == expected


def test_wrong_sha256_is_rejected(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    evidence = evidence.model_copy(update={"sha256": "incorrect"})

    with pytest.raises(
        ValueError,
        match="SHA-256",
    ):
        repository.save_audit(evidence)


def test_wrong_size_is_rejected(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    evidence = evidence.model_copy(update={"size_bytes": 999999})

    with pytest.raises(
        ValueError,
        match="size_bytes",
    ):
        repository.save_audit(evidence)


def test_integrity_verification_succeeds(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    assert repository.verify_evidence_integrity(evidence.evidence_id)


def test_integrity_details_are_complete(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    details = repository.get_integrity_details(evidence.evidence_id)

    assert details["exists"] is True

    assert details["raw_sha256_matches"] is True

    assert details["record_sha256_matches"] is True

    assert details["size_matches"] is True


def test_tampered_raw_data_is_detected(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    with repository._connect() as connection:
        connection.execute(
            """
            UPDATE evidence
            SET raw_data = ?
            WHERE evidence_id = ?
            """,
            (
                b"TAMPERED",
                evidence.evidence_id,
            ),
        )

    assert not repository.verify_evidence_integrity(evidence.evidence_id)


def test_tampered_metadata_is_detected(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    with repository._connect() as connection:
        connection.execute(
            """
            UPDATE evidence
            SET instance_name = ?
            WHERE evidence_id = ?
            """,
            (
                "tampered-instance",
                evidence.evidence_id,
            ),
        )

    assert not repository.verify_evidence_integrity(evidence.evidence_id)


def test_missing_evidence_fails_integrity_check(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    assert not repository.verify_evidence_integrity("does-not-exist")

    details = repository.get_integrity_details("does-not-exist")

    assert details["exists"] is False


def test_count_evidence(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    repository.save_audit(make_evidence(evidence_id="evidence-001"))

    repository.save_audit(make_evidence(evidence_id="evidence-002"))

    assert repository.count_evidence() == 2


def test_list_by_tenant(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    repository.save_audit(
        make_evidence(
            evidence_id="evidence-a",
            tenant_id="tenant-a",
        )
    )

    repository.save_audit(
        make_evidence(
            evidence_id="evidence-b",
            tenant_id="tenant-b",
        )
    )

    rows = repository.list_evidence(tenant_id="tenant-b")

    assert len(rows) == 1

    assert rows[0]["tenant_id"] == ("tenant-b")


def test_list_by_instance(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    repository.save_audit(
        make_evidence(
            evidence_id="evidence-web",
            instance_name="web-b",
        )
    )

    repository.save_audit(
        make_evidence(
            evidence_id="evidence-db",
            instance_name="db-b",
        )
    )

    rows = repository.list_evidence(instance_name="web-b")

    assert len(rows) == 1

    assert rows[0]["instance_name"] == ("web-b")


def test_get_evidence_record(
    tmp_path,
):
    repository = SQLiteEvidenceRepository(tmp_path / "evidence.db")

    evidence = make_evidence()

    repository.save_audit(evidence)

    record = repository.get_evidence_record(evidence.evidence_id)

    assert record is not None

    assert record.evidence_id == (evidence.evidence_id)

    assert record.raw_data == (evidence.raw_data)

    assert record.sha256 == (evidence.sha256)

    assert record.size_bytes == (evidence.size_bytes)
