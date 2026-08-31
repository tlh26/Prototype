# acquisition/collectors/audit.py

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from acquisition.collectors.base import (
    CollectorError,
    EvidenceCollector,
)
from acquisition.collectors.hostExec import HostExecutor
from common.hashing import HashingService
from evidence.tenant import TenantContext


# Example:
#
# msg=audit(08/27/2026 19:35:34.612:6622)
#
# The final numeric component is the audit serial number.
_AUDIT_SEQUENCE_RE = re.compile(
    rb"msg=audit\([^)]*:(\d+)\)"
)


# Example:
#
# subj=incus-tenant-b_web-b_</var/lib/incus>//&:...
#
# We intentionally only depend on the stable prefix:
#
#     incus-<project>_<instance>
#
# Everything after the instance name belongs to the Incus/AppArmor
# security-context representation and is preserved as raw evidence.
_INCUS_SUBJECT_RE = re.compile(
    rb"\bsubj=incus-([^_\s]+)_([^_\s]+)"
)


class AuditEvent(BaseModel):
    """
    A complete audit event grouped by its audit serial number.

    An audit event can consist of multiple records, e.g.:

        PROCTITLE
        PATH
        CWD
        EXECVE
        SYSCALL

    All records sharing the same serial number belong to the same
    audit event.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    sequence: int
    raw_data: bytes
    tenant_id: str | None
    instance_id: str | None


class AuditEvidence(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str
    tenant_id: str
    tenant_hash: str
    project_id: str
    instance_name: str | None
    scope: str
    source: str
    source_path: str
    collected_at: datetime
    raw_data: bytes
    sha256: str
    size_bytes: int
    sequence_start: int | None = None
    sequence_end: int | None = None


class AuditCollector(EvidenceCollector[AuditEvidence]):
    """
    Collect Linux auditd evidence from the Ubuntu/Incus host.

    Auditd runs on the host rather than inside the Incus instances.
    Incus/AppArmor security subjects identify which project and
    instance generated an event.

    Acquisition flow:

        Ubuntu/Incus host
              |
              v
        ausearch -ts recent
              |
              v
        complete audit events
              |
              v
        subj=incus-<project>_<instance>
              |
              v
        CaptureTarget filtering
              |
              v
        raw audit evidence
              |
              v
        SHA-256
              |
              v
        AuditEvidence

    The raw audit records are never modified.
    """

    DEFAULT_AUDIT_PATH = "/var/log/audit/audit.log"

    @property
    def source(self) -> str:
        return "auditd"

    def __init__(
        self,
        executor: HostExecutor,
        hashing_service: HashingService | None = None,
    ) -> None:
        self.executor = executor
        self.hashing_service = (
            hashing_service or HashingService()
        )

    def collect(
        self,
        *,
        tenant: TenantContext,
        instance_name: str,
        audit_path: str = DEFAULT_AUDIT_PATH,
    ) -> AuditEvidence:
        """
        Acquire audit events from the Ubuntu/Incus host and filter
        them for the requested tenant/project and instance.

        `audit_path` is retained as evidence metadata for compatibility
        with the existing evidence model. Acquisition itself is performed
        through `ausearch` on the host.
        """

        if not instance_name.strip():
            raise ValueError(
                "instance_name must not be empty"
            )

        if not audit_path.startswith("/"):
            raise ValueError(
                "audit_path must be absolute"
            )

        try:
            result = self.executor.exec(
                command=[
                    "cat",
                    audit_path,
            ],
        )
        except Exception as exc:
            raise CollectorError(
                "Failed to acquire host audit evidence",
                source=self.source,
            ) from exc

        if result.returncode != 0:
            stderr = result.stderr.decode(
                errors="replace"
            ).strip()

            raise CollectorError(
                "Failed to acquire host audit evidence"
                + (
                    f": {stderr}"
                    if stderr
                    else ""
                ),
                source=self.source,
            )

        raw_data = result.stdout

        if not raw_data:
            raise CollectorError(
                "No audit evidence returned by ausearch",
                source=self.source,
            )

        events = self._parse_events(raw_data)

        matching_events = [
            event
            for event in events
            if self._matches_target(
                event=event,
                tenant=tenant,
                instance_name=instance_name,
            )
        ]

        if not matching_events:
            raise CollectorError(
                "No audit events found for "
                f"{tenant.platform_project_id}/{instance_name}",
                source=self.source,
            )

        # Preserve the original audit records exactly as returned
        # by ausearch. We only concatenate complete event groups.
        filtered_raw_data = b"".join(
            event.raw_data
            for event in matching_events
        )

        if not filtered_raw_data:
            raise CollectorError(
                "Matching audit events contained no raw data",
                source=self.source,
            )

        evidence_hash = self.hashing_service.sha256(
            filtered_raw_data
        )

        sequences = [
            event.sequence
            for event in matching_events
        ]

        return AuditEvidence(
            evidence_id=str(uuid.uuid4()),
            tenant_id=tenant.tenant_id,
            tenant_hash=tenant.tenant_hash,
            project_id=tenant.platform_project_id,
            instance_name=instance_name,
            scope=(
                f"{tenant.platform_project_id}/"
                f"{instance_name}"
            ),
            source=self.source,
            source_path=audit_path,
            collected_at=datetime.now(timezone.utc),
            raw_data=filtered_raw_data,
            sha256=evidence_hash,
            size_bytes=len(filtered_raw_data),
            sequence_start=min(sequences),
            sequence_end=max(sequences),
        )

    @classmethod
    def _parse_events(
        cls,
        raw_data: bytes,
    ) -> list[AuditEvent]:
        """
        Parse ausearch output into complete audit events.

        ausearch separates audit events using:

            ----

        Every record belonging to one event has the same:

            msg=audit(...:<serial>)

        The complete event is therefore grouped by serial number.

        Events without an audit serial number are ignored because they
        cannot be reliably correlated to an Incus instance.
        """

        records = cls._split_audit_records(raw_data)

        grouped: dict[int, list[bytes]] = {}
        subjects: dict[int, tuple[str | None, str | None]] = {}

        for record in records:
            sequence = cls._extract_sequence(record)

            if sequence is None:
                continue

            grouped.setdefault(sequence, []).append(record)

            tenant_id, instance_id = (
                cls._extract_incus_subject(record)
            )

            if tenant_id is not None and instance_id is not None:
                subjects[sequence] = (
                    tenant_id,
                    instance_id,
                )

        events: list[AuditEvent] = []

        for sequence in sorted(grouped):
            records_for_event = grouped[sequence]

            # Keep the exact record bytes. We only join records that
            # ausearch has already identified as belonging to the same
            # audit serial.
            event_raw = b"".join(records_for_event)

            tenant_id, instance_id = subjects.get(
                sequence,
                (None, None),
            )

            events.append(
                AuditEvent(
                    sequence=sequence,
                    raw_data=event_raw,
                    tenant_id=tenant_id,
                    instance_id=instance_id,
                )
            )

        return events

    @staticmethod
    def _split_audit_records(
        raw_data: bytes,
    ) -> list[bytes]:
        """
        Split audit data into individual audit records.

        Supports both:

        1. Native /var/log/audit/audit.log
           - one record per line

        2. ausearch output
           - records/events separated by '----'

        The parser itself subsequently groups records by audit
        serial number.
        """

        records: list[bytes] = []

        # ausearch format
        if b"----" in raw_data:
            for block in raw_data.split(b"----"):
                block = block.strip()

                if not block:
                    continue

                for line in block.splitlines(keepends=True):
                    line = line.strip()

                    if (
                        line
                        and b"msg=audit(" in line
                    ):
                        records.append(
                            line + b"\n"
                        )

            return records

        # Native audit.log format
        for line in raw_data.splitlines(keepends=True):
            line = line.strip()

            if (
                line
                and b"msg=audit(" in line
            ):
                records.append(
                    line + b"\n"
                )

        return records

    @staticmethod
    def _extract_sequence(
        record: bytes,
    ) -> int | None:
        """
        Extract the audit serial number from one audit record.
        """

        match = _AUDIT_SEQUENCE_RE.search(record)

        if not match:
            return None

        return int(match.group(1))

    @staticmethod
    def _extract_incus_subject(
        record: bytes,
    ) -> tuple[str | None, str | None]:
        """
        Extract:

            tenant/project
            instance

        from:

            subj=incus-tenant-b_web-b_...

        Returns:

            ("tenant-b", "web-b")
        """

        match = _INCUS_SUBJECT_RE.search(record)

        if not match:
            return None, None

        tenant_id = match.group(1).decode(
            errors="replace"
        )

        instance_id = match.group(2).decode(
            errors="replace"
        )

        return tenant_id, instance_id

    @staticmethod
    def _matches_target(
        *,
        event: AuditEvent,
        tenant: TenantContext,
        instance_name: str,
    ) -> bool:
        """
        Determine whether an audit event belongs to the requested
        CaptureTarget.

        Both project and instance must match.

        This prevents events from:

            tenant-b/api-b
            tenant-b/db-b
            tenant-a/web-a

        from being captured for:

            tenant-b/web-b
        """

        expected_project = tenant.platform_project_id

        return (
            event.tenant_id == expected_project
            and event.instance_id == instance_name
        )

    @staticmethod
    def _extract_sequence_range(
        raw_data: bytes,
    ) -> tuple[int | None, int | None]:
        """
        Extract the minimum and maximum audit serial numbers from
        raw audit evidence.

        Kept for compatibility with existing tests/code.
        """

        sequences = [
            int(match.group(1))
            for match in _AUDIT_SEQUENCE_RE.finditer(
                raw_data
            )
        ]

        if not sequences:
            return None, None

        return min(sequences), max(sequences)