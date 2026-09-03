from acquisition.collectors.auditAttributor import (
    IncusAuditAttributor,
)
from acquisition.collectors.audit import (
    AuditCollector,
)
from acquisition.checkpoint import (
    AuditCheckpoint,
    CheckpointStore,
)


def test_incus_subject_is_attributed():
    raw = (
        b"type=SYSCALL "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"subj=incus-tenant-b_web-b_test"
    )

    result = (
        IncusAuditAttributor()
        .attribute(raw)
    )

    assert result.tenant_id == "tenant-b"
    assert result.instance_id == "web-b"
    assert result.method == "incus_subject"

def test_unattributed_event():
    raw = (
        b"type=SYSCALL "
        b"msg=audit(08/27/2026 19:35:34.612:6622): "
        b"uid=0"
    )

    result = (
        IncusAuditAttributor()
        .attribute(raw)
    )

    assert result.tenant_id is None
    assert result.instance_id is None
    assert result.method == "unattributed"




def test_audit_event_id_is_deterministic():
    raw = b"test audit event"

    first = (
        AuditCollector._make_event_id(
            host_id="test-host1",
            sequence=100,
            raw_data=raw,
        )
    )

    second = (
        AuditCollector._make_event_id(
            host_id="test-host2",
            sequence=100,
            raw_data=raw,
        )
    )

    assert first == second

def test_checkpoint_round_trip(
    tmp_path,
):
    path = (
        tmp_path
        / "audit-checkpoint.json"
    )

    store = CheckpointStore(path)

    checkpoint = AuditCheckpoint(
        source_path="/var/log/audit/audit.log",
        file_device=10,
        file_inode=20,
        offset=300,
        last_sequence=6622,
        pending_data=b"pending audit data",
    )

    store.save(checkpoint)

    loaded = store.load()

    assert loaded == checkpoint