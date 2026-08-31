from pathlib import Path

from acquisition.collectors.audit import AuditCollector
from acquisition.collectors.hostExec import (
    HostCommandResult,
    HostExecutor,
)
from common.hashing import HashingService
from evidence.tenant import TenantContext


def test_host_executor_executes_local_command():
    executor = HostExecutor()

    result = executor.exec(
        command=["echo", "hello"],
    )

    assert result.returncode == 0
    assert result.stdout.strip() == b"hello"


class FakeHostExecutor(HostExecutor):

    def __init__(self, stdout: bytes):
        self.stdout = stdout
        self.commands = []

    def exec(self, *, command: list[str]) -> HostCommandResult:
        self.commands.append(command)

        return HostCommandResult(
            stdout=self.stdout,
            stderr=b"",
            returncode=0,
        )


def test_audit_collector_uses_host_ausearch():

    raw = Path(
        "tests/fixtures/audit_web_b.txt"
    ).read_bytes()

    executor = FakeHostExecutor(raw)

    collector = AuditCollector(
        executor=executor,
    )

    tenant = TenantContext(
        tenant_id="tenant-b",
        tenant_name="Tenant B",
        tenant_hash=HashingService().sha256(
            b"tenant-b"
        ),
        platform="incus",
        platform_project_id="tenant-b",
    )

    collector.collect(
        tenant=tenant,
        instance_name="web-b",
    )

    assert executor.commands[0] == [
        "ausearch",
        "-ts",
        "recent",
    ]