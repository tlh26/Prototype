from types import SimpleNamespace

from acquisition.checkpoint import CheckpointStore
from acquisition.collectors.audit import AuditCollector
from acquisition.collectors.auditAttributor import IncusAuditAttributor


AUDIT_LOG = "/var/log/audit/audit.log"


class MockHostExecutor:
    """
    Mock implementation of HostExecutor.

    It supports the two commands used by AuditCollector:

        stat -c "%d %i %s" <audit-log>
        dd if=<audit-log> bs=1 skip=<offset> count=<size> status=none
    """

    def __init__(self, audit_data: bytes):
        self.audit_data = audit_data
        self.commands: list[list[str]] = []

    def exec(self, *, command: list[str]):
        self.commands.append(command)

        if command[0] == "stat":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    f"10 20 {len(self.audit_data)}\n"
                ).encode(),
                stderr=b"",
            )

        if command[0] == "dd":
            skip = 0
            count = len(self.audit_data)

            for argument in command:
                if argument.startswith("skip="):
                    skip = int(
                        argument.split("=", 1)[1]
                    )

                elif argument.startswith("count="):
                    count = int(
                        argument.split("=", 1)[1]
                    )

            return SimpleNamespace(
                returncode=0,
                stdout=self.audit_data[
                    skip:skip + count
                ],
                stderr=b"",
            )

        raise AssertionError(
            f"Unexpected host command: {command}"
        )


def audit_record(
    sequence: int,
    subject: str,
) -> bytes:
    return (
        b"type=SYSCALL "
        + (
            f"msg=audit("
            f"08/27/2026 19:35:34.612:"
            f"{sequence}"
            f"): "
        ).encode()
        + f"subj={subject}\n".encode()
    )


def create_collector(
    tmp_path,
    audit_data: bytes,
):
    executor = MockHostExecutor(
        audit_data
    )

    checkpoint_store = CheckpointStore(
        tmp_path / "audit-checkpoint.json"
    )

    collector = AuditCollector(
        executor=executor,
        checkpoint_store=checkpoint_store,
        attributor=IncusAuditAttributor(),
        host_id="test-host",
    )

    return collector, executor


def test_audit_collector_collect_new_full_flow(
    tmp_path,
):
    """
    Verify the complete AuditCollector acquisition flow
    using a mocked HostExecutor.

    Covers:

        host stat
            ↓
        host read
            ↓
        incremental parsing
            ↓
        event grouping
            ↓
        Incus attribution
            ↓
        AuditEvidence
            ↓
        checkpoint
    """

    audit_data = (
        audit_record(
            100,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            100,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            101,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            102,
            "incus-tenant-b_db-b_test",
        )
    )

    collector, executor = create_collector(
        tmp_path,
        audit_data,
    )

    result = collector.collect_new(
        audit_path=AUDIT_LOG
    )

    evidence = result.evidence
    checkpoint = result.checkpoint

    # ---------------------------------------------------------
    # Evidence was produced
    # ---------------------------------------------------------

    assert evidence

    # The highest sequence is held back because the event
    # may still receive additional audit records.
    sequences = {
        item.sequence_start
        for item in evidence
    }

    assert sequences == {100, 101}

    # ---------------------------------------------------------
    # Tenant / instance attribution
    # ---------------------------------------------------------

    web_evidence = [
        item
        for item in evidence
        if item.instance_name == "web-b"
    ]

    assert len(web_evidence) == 2

    for item in web_evidence:
        assert item.tenant_id == "tenant-b"
        assert item.project_id == "tenant-b"
        assert item.instance_name == "web-b"
        assert item.attribution_method == "incus_subject"

    # ---------------------------------------------------------
    # Raw evidence preserved
    # ---------------------------------------------------------

    for item in evidence:
        assert isinstance(
            item.raw_data,
            bytes,
        )

        assert item.raw_data

        assert item.size_bytes == len(
            item.raw_data
        )

    # ---------------------------------------------------------
    # SHA-256 integrity
    # ---------------------------------------------------------

    for item in evidence:
        assert len(item.sha256) == 64

    # ---------------------------------------------------------
    # Provenance
    # ---------------------------------------------------------

    for item in evidence:
        assert item.source == "auditd"
        assert item.source_path == AUDIT_LOG
        assert item.acquisition_layer == "host"
        assert item.acquired_from == "test-host"

    # ---------------------------------------------------------
    # Checkpoint
    # ---------------------------------------------------------

    assert checkpoint.source_path == AUDIT_LOG
    assert checkpoint.file_device == 10
    assert checkpoint.file_inode == 20

    assert checkpoint.last_sequence == 101

    # Sequence 102 is retained as pending.
    assert checkpoint.pending_data

    assert (
        b":102):"
        in checkpoint.pending_data
    )

    # ---------------------------------------------------------
    # Host executor was actually used
    # ---------------------------------------------------------

    assert len(executor.commands) == 2

    assert executor.commands[0][0] == "stat"
    assert executor.commands[1][0] == "dd"


def test_audit_collector_commit_checkpoint(
    tmp_path,
):
    """
    Verify that the checkpoint produced by collection
    can subsequently be committed and loaded.
    """

    audit_data = (
        audit_record(
            100,
            "incus-tenant-b_web-b_test",
        )
        + audit_record(
            101,
            "incus-tenant-b_web-b_test",
        )
    )

    collector, _ = create_collector(
        tmp_path,
        audit_data,
    )

    result = collector.collect_new(
        audit_path=AUDIT_LOG
    )

    collector.commit_checkpoint(
        result.checkpoint
    )

    stored = collector.checkpoint_store.load()

    assert stored == result.checkpoint