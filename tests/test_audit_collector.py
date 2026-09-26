# tests/test_audit_collector.py
from unittest.mock import Mock

from acquisition.collectors.audit import (
    AuditCollector,
)
from acquisition.collectors.base import CollectorError
from acquisition.collectors.incusExec import (
    IncusCommandResult,
)
import hashlib
import pytest

SAMPLE_AUDIT = b"""\
type=PROCTITLE msg=audit(08/24/2026 18:07:18.464:933) : proctitle=touch /etc/passwd
type=PATH msg=audit(08/24/2026 18:07:18.464:933) : item=0 name=/etc/passwd inode=133136 dev=fd:02 mode=file,644 ouid=root ogid=root rdev=00:00 nametype=NORMAL
type=CWD msg=audit(08/24/2026 18:07:18.464:933) : cwd=/home/tood
type=SYSCALL msg=audit(08/24/2026 18:07:18.464:933) : arch=aarch64 syscall=openat success=yes exit=3 auid=tood uid=root gid=root euid=root comm=touch exe=/usr/bin/touch key=identity
"""


def make_tenant():
    tenant = Mock()

    tenant.tenant_id = "tenant-b"
    tenant.tenant_hash = "tenant-hash-b"
    tenant.platform_project_id = "tenant-b"

    return tenant


def test_audit_collector_preserves_raw_bytes():

    executor = Mock()

    executor.exec.return_value = IncusCommandResult(
        stdout=SAMPLE_AUDIT,
        stderr=b"",
        returncode=0,
    )

    collector = AuditCollector(executor=executor)

    evidence = collector.collect(
        tenant=make_tenant(),
        instance_name="web-b",
    )

    assert evidence.raw_data == SAMPLE_AUDIT


def test_audit_hash_matches_raw_evidence():

    executor = Mock()

    executor.exec.return_value = IncusCommandResult(
        stdout=SAMPLE_AUDIT,
        stderr=b"",
        returncode=0,
    )

    collector = AuditCollector(executor=executor)

    evidence = collector.collect(
        tenant=make_tenant(),
        instance_name="web-b",
    )

    expected = hashlib.sha256(SAMPLE_AUDIT).hexdigest()

    assert evidence.sha256 == expected


def test_audit_collection_uses_tenant_project():

    executor = Mock()

    executor.exec.return_value = IncusCommandResult(
        stdout=SAMPLE_AUDIT,
        stderr=b"",
        returncode=0,
    )

    collector = AuditCollector(executor=executor)

    tenant = make_tenant()

    collector.collect(
        tenant=tenant,
        instance_name="web-b",
    )

    executor.exec.assert_called_once_with(
        project="tenant-b",
        instance="web-b",
        command=[
            "cat",
            "/var/log/audit/audit.log",
        ],
    )


def test_audit_sequence_range():

    executor = Mock()

    executor.exec.return_value = IncusCommandResult(
        stdout=SAMPLE_AUDIT,
        stderr=b"",
        returncode=0,
    )

    collector = AuditCollector(executor=executor)

    evidence = collector.collect(
        tenant=make_tenant(),
        instance_name="web-b",
    )

    assert evidence.sequence_start == 933
    assert evidence.sequence_end == 933


def test_empty_audit_log_is_rejected():

    executor = Mock()

    executor.exec.return_value = IncusCommandResult(
        stdout=b"",
        stderr=b"",
        returncode=0,
    )

    collector = AuditCollector(executor=executor)

    with pytest.raises(CollectorError):  ##with pytest.raises(CollectorError):
        collector.collect(
            tenant=make_tenant(),
            instance_name="web-b",
        )
