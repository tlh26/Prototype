from datetime import datetime, timezone

from acquisition.collectors.audit import AuditEvidence
from storage.evidenceRepo import (
    SQLiteEvidenceRepository,
)


SAMPLE = b"test audit evidence\n"


def make_evidence() -> AuditEvidence:

    import hashlib

    return AuditEvidence(
        evidence_id="evidence-001",

        tenant_id="tenant-b",
        tenant_hash="tenant-hash-b",

        project_id="tenant-b",

        instance_name="web-b",

        source="auditd",
        source_path="/var/log/audit/audit.log",

        collected_at=datetime.now(
            timezone.utc
        ),

        raw_data=SAMPLE,

        sha256=hashlib.sha256(
            SAMPLE
        ).hexdigest(),

        size_bytes=len(SAMPLE),

        sequence_start=100,
        sequence_end=100,
    )


def test_repository_stores_raw_evidence(
    tmp_path,
):

    database = (
        tmp_path / "evidence.db"
    )

    repository = SQLiteEvidenceRepository(
        database
    )

    evidence = make_evidence()

    repository.save_audit(
        evidence
    )

    stored = repository.get_evidence(
        "evidence-001"
    )

    assert stored is not None

    assert bytes(
        stored["raw_data"]
    ) == SAMPLE

    assert stored["sha256"] == evidence.sha256

    assert stored["tenant_id"] == "tenant-b"

    assert stored["project_id"] == "tenant-b"

    assert stored["instance_name"] == "web-b"

    assert stored["source"] == "auditd"

def test_repository_stores_record_hash(
    tmp_path,
):

    database = (
        tmp_path / "evidence.db"
    )

    repository = SQLiteEvidenceRepository(
        database
    )

    evidence = make_evidence()

    repository.save_audit(
        evidence
    )

    stored = repository.get_evidence(
        "evidence-001"
    )

    assert stored is not None

    record_hash = stored[
        "record_sha256"
    ]

    assert record_hash is not None
    assert len(record_hash) == 64