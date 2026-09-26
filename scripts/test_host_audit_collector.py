from __future__ import annotations

import argparse
from pathlib import Path

from click.core import batch
from requests.packages import target

from acquisition.checkpoint import CheckpointStore
from acquisition.collectors.audit import AuditCollector
from acquisition.collectors.auditAttributor import IncusAuditAttributor
from acquisition.collectors.hostExec import HostExecutor

AUDIT_PATH = "/var/log/audit/audit.log"
CHECKPOINT_PATH = Path("/tmp/evidence-host-audit-checkpoint.json")


def lookup_tenant(project_id: str):
    """
    Temporary tenant lookup for live testing.

    Replace this with the real TenantResolver after the
    host-level acquisition path has been validated.
    """
    from evidence.enums import CloudPlatform
    from evidence.tenant import TenantContext

    known = {
        "tenant-a": TenantContext(
            tenant_id="tenant-a",
            tenant_name="tenant-a",
            tenant_hash="",
            platform=CloudPlatform.INCUS,
            platform_project_id="tenant-a",
        ),
        "tenant-b": TenantContext(
            tenant_id="tenant-b",
            tenant_name="tenant-b",
            tenant_hash="",
            platform=CloudPlatform.INCUS,
            platform_project_id="tenant-b",
        ),
    }

    return known.get(project_id)


def build_collector() -> AuditCollector:
    checkpoint_store = CheckpointStore(CHECKPOINT_PATH)
    attributor = IncusAuditAttributor()

    executor = HostExecutor(use_sudo=True)

    return AuditCollector(
        executor=executor,
        checkpoint_store=checkpoint_store,
        attributor=attributor,
        host_id="incus-host-01",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("Smoke-test the host-level Incus audit collector.")
    )

    parser.add_argument(
        "--commit",
        action="store_true",
        help=(
            "Commit the returned checkpoint. "
            "Only use this after verifying/persisting evidence."
        ),
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help=("Delete the test checkpoint before collecting."),
    )

    args = parser.parse_args()

    if args.reset and CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.unlink()
        print(f"Removed checkpoint: {CHECKPOINT_PATH}")

    collector = build_collector()

    print()
    print("=" * 70)
    print("LIVE INCUS HOST AUDIT COLLECTOR")
    print("=" * 70)

    print(f"Audit path:     {AUDIT_PATH}")
    print(f"Checkpoint:     {CHECKPOINT_PATH}")
    print(f"Checkpoint mode: {'COMMIT' if args.commit else 'DRY RUN'}")
    print()

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    try:
        batch = collector.collect_new(audit_path=AUDIT_PATH)
    except Exception as exc:
        print("COLLECTION FAILED")
        print(f"{type(exc).__name__}: {exc}")
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Collection summary
    # ------------------------------------------------------------------

    print("Collection successful.")
    print()
    print(f"Evidence records : {len(batch.evidence)}")
    print(f"Next offset      : {batch.checkpoint.offset}")
    print(f"Last sequence    : {batch.checkpoint.last_sequence}")
    print(f"Pending bytes    : " f"{len(batch.checkpoint.pending_data)}")

    target = b"/tmp/evidence-live-test-005"

    matches = [evidence for evidence in batch.evidence if target in evidence.raw_data]

    print()
    print("=" * 70)
    print("TARGET EVENT CHECK")
    print("=" * 70)
    print(f"Target            : {target.decode()}")
    print(f"Matches            : {len(matches)}")

    for evidence in matches:
        print()
        print(f"Evidence ID       : {evidence.evidence_id}")
        print(f"Sequence          : {evidence.sequence_start}")
        print(f"Tenant            : {evidence.tenant_id}")
        print(f"Instance          : {evidence.instance_name}")
        print(f"Scope             : {evidence.scope}")
        print(f"Attribution       : {evidence.attribution_method}")

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    for index, evidence in enumerate(
        batch.evidence,
        start=1,
    ):
        print()
        print("-" * 70)
        print(f"Evidence #{index}")
        print("-" * 70)

        print(f"Evidence ID       : {evidence.evidence_id}")
        print(f"Tenant            : {evidence.tenant_id}")
        print(f"Project           : {evidence.project_id}")
        print(f"Instance          : {evidence.instance_name}")
        print(f"Scope             : {evidence.scope}")
        print(f"Sequence start    : {evidence.sequence_start}")
        print(f"Sequence end      : {evidence.sequence_end}")
        print(f"Source            : {evidence.source}")
        print(f"Source path       : {evidence.source_path}")
        print(f"Acquisition layer : {evidence.acquisition_layer}")
        print(f"Acquired from     : {evidence.acquired_from}")
        print(f"Attribution       : {evidence.attribution_method}")
        print(f"SHA-256           : {evidence.sha256}")
        print(f"Size               : {evidence.size_bytes}")

    # ------------------------------------------------------------------
    # Checkpoint
    # ------------------------------------------------------------------

    if args.commit:
        collector.commit_checkpoint(batch.checkpoint)

        print()
        print("=" * 70)
        print("CHECKPOINT COMMITTED")
        print("=" * 70)
        print(f"Checkpoint saved to: {CHECKPOINT_PATH}")

    else:
        print()
        print("=" * 70)
        print("CHECKPOINT NOT COMMITTED")
        print("=" * 70)
        print("This was a dry run. No acquisition cursor was advanced.")


if __name__ == "__main__":
    main()
