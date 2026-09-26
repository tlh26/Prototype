from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from acquisition.captureTarget import CaptureTarget
from acquisition.collectorRegistry import CollectorRegistry
from acquisition.evidenceCaptureService import (
    EvidenceCaptureService,
)
from acquisition.collectors.audit import AuditCollector
from acquisition.collectors.incusExec import IncusExecutor
from evidence.enums import CloudPlatform
from evidence.tenant import TenantContext
from storage.evidenceRepo import (
    SQLiteEvidenceRepository,
)


def build_tenant(
    project_id: str,
) -> TenantContext:

    return TenantContext(
        tenant_id=project_id,
        tenant_name=project_id,
        tenant_hash=f"hash-{project_id}",
        platform=CloudPlatform.INCUS,
        platform_project_id=project_id,
    )


def build_service(
    database_path: str,
) -> EvidenceCaptureService:

    executor = IncusExecutor()

    audit_collector = AuditCollector(executor=executor)

    registry = CollectorRegistry()

    registry.register(audit_collector)

    repository = SQLiteEvidenceRepository(database_path)

    return EvidenceCaptureService(
        registry=registry,
        repository=repository,
    )


def main() -> None:

    parser = argparse.ArgumentParser(
        description="Capture forensic evidence from an Incus instance."
    )

    parser.add_argument(
        "--project",
        required=True,
        help="Incus project / tenant identifier",
    )

    parser.add_argument(
        "--instance",
        required=True,
        help="Incus instance name",
    )

    parser.add_argument(
        "--database",
        default="data/evidence.db",
        help="SQLite evidence database path",
    )

    args = parser.parse_args()

    tenant = build_tenant(args.project)

    target = CaptureTarget(
        tenant=tenant,
        instance_name=args.instance,
    )

    service = build_service(args.database)

    print()
    print("=" * 60)
    print("Evidence Capture")
    print("=" * 60)

    print(f"Tenant:   {target.tenant_id}")

    print(f"Project:  {target.project_id}")

    print(f"Instance: {target.instance_name}")

    print()

    manifest = service.capture(
        target=target,
        sources=[
            "auditd",
        ],
    )

    for result in manifest.sources:

        if result.status.value == "success":

            print(
                f"[OK] {result.source:<12} "
                f"{result.size_bytes} bytes "
                f"SHA256={result.sha256}"
            )

        else:

            print(f"[FAILED] {result.source:<12} " f"{result.error}")

    print()

    print(f"Capture ID: {manifest.capture_id}")

    print(f"Status:     {manifest.status.value}")

    print(f"Evidence:   {manifest.evidence_count}")

    print("=" * 60)


if __name__ == "__main__":
    main()
