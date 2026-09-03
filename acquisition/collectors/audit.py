# acquisition/collectors/audit.py

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from acquisition.checkpoint import (
    AuditCheckpoint,
    CheckpointStore,
)
from acquisition.collectors.auditAttributor import (
    AuditAttribution,
    IncusAuditAttributor,
)
from acquisition.collectors.base import (
    CollectorError,
    EvidenceCollector,
)
from acquisition.collectors.hostExec import HostExecutor
from common.hashing import HashingService
from evidence.tenant import TenantContext


# ---------------------------------------------------------------------------
# Audit sequence
# ---------------------------------------------------------------------------

_AUDIT_SEQUENCE_RE = re.compile(
    rb"msg=audit\([^)]*:(\d+)\)"
)


# ---------------------------------------------------------------------------
# Acquisition-level event
# ---------------------------------------------------------------------------

class AuditEvent(BaseModel):
    """
    A complete logical audit event.

    One audit event may contain several audit records:

        SYSCALL
        PATH
        PATH
        CWD
        EXECVE
        PROCTITLE

    All records belonging to the same event share the same
    audit serial number.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    sequence: int
    raw_data: bytes


# ---------------------------------------------------------------------------
# Evidence model
# ---------------------------------------------------------------------------

class AuditEvidence(BaseModel):
    """
    Immutable host-level audit evidence.

    raw_data contains the original audit records.

    The raw records are not semantically rewritten during acquisition.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str

    tenant_id: str | None
    tenant_hash: str | None

    project_id: str | None
    instance_name: str | None

    scope: str

    source: str
    source_path: str

    acquisition_layer: str
    acquired_from: str

    attribution_method: str

    collected_at: datetime

    raw_data: bytes
    sha256: str
    size_bytes: int

    sequence_start: int | None = None
    sequence_end: int | None = None


# ---------------------------------------------------------------------------
# Collection result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditCollectionResult:
    """
    Result of one incremental host audit collection cycle.

    checkpoint represents the cursor that may be committed after
    the caller has successfully persisted all returned evidence.
    """

    evidence: tuple[AuditEvidence, ...]

    checkpoint: AuditCheckpoint


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class AuditCollector(
    EvidenceCollector[AuditEvidence]
):
    """
    Incremental Linux auditd collector for an Incus host.

    Responsibilities:

        1. Read new host audit-log bytes.
        2. Reconstruct logical audit events.
        3. Attribute events to Incus project/instance.
        4. Preserve raw event bytes.
        5. Calculate SHA-256 integrity hashes.
        6. Produce immutable AuditEvidence.
        7. Produce a checkpoint for the caller to commit.

    This collector does NOT:

        - collect nginx logs;
        - collect authentication logs;
        - perform evidence correlation;
        - write directly to SQLite;
        - manage tenant ContextVars.

    Auditd runs on the Incus host, so this collector must execute
    against the host rather than an Incus container.
    """

    DEFAULT_AUDIT_PATH = (
        "/var/log/audit/audit.log"
    )

    def __init__(
        self,
        executor: HostExecutor,
        checkpoint_store: CheckpointStore,
        hashing_service: HashingService | None = None,
        attributor: IncusAuditAttributor | None = None,
        host_id: str = "incus-host",
    ) -> None:
        self.executor = executor

        self.checkpoint_store = (
            checkpoint_store
        )

        self.hashing_service = (
            hashing_service
            or HashingService()
        )

        self.attributor = (
            attributor
            or IncusAuditAttributor()
        )

        self.host_id = host_id

    @property
    def source(self) -> str:
        return "auditd"

    # =======================================================================
    # PUBLIC API
    # =======================================================================

    def collect_new(
        self,
        *,
        audit_path: str = DEFAULT_AUDIT_PATH,
    ) -> AuditCollectionResult:
        """
        Acquire only new audit data since the previous checkpoint.

        This method does NOT commit the checkpoint.

        The caller should:

            1. call collect_new()
            2. persist all returned evidence
            3. commit the returned checkpoint
        """

        self._validate_audit_path(
            audit_path
        )

        checkpoint = (
            self.checkpoint_store.load()
        )

        metadata = self._stat_audit_file(
            audit_path
        )

        start_offset = (
            self._calculate_start_offset(
                checkpoint=checkpoint,
                metadata=metadata,
                audit_path=audit_path,
            )
        )

        if metadata["size"] < start_offset:
            raise CollectorError(
                "Audit log size is smaller than "
                "the checkpoint offset",
                source=self.source,
            )

        new_size = (
            metadata["size"]
            - start_offset
        )

        new_data = self._read_audit_range(
            audit_path=audit_path,
            offset=start_offset,
            size=new_size,
        )

        previous_pending = (
            checkpoint.pending_data
            if checkpoint is not None
            else b""
        )

        combined_data = (
            previous_pending
            + new_data
        )

        events, pending_data = (
            self._parse_incremental_data(
                combined_data
            )
        )

        evidence: list[AuditEvidence] = []

        for event in events:
            attribution = (
                self.attributor.attribute(
                    event.raw_data
                )
            )

            item = self._build_evidence(
                event=event,
                attribution=attribution,
                audit_path=audit_path,
            )

            evidence.append(item)

        # ------------------------------------------------------------------
        # Calculate the safe checkpoint.
        #
        # pending_data has NOT been safely completed, so the offset must
        # point to the beginning of pending_data.
        # ------------------------------------------------------------------

        pending_size = len(
            pending_data
        )

        safe_offset = (
            metadata["size"]
            - pending_size
        )

        last_sequence = (
            max(
                (
                    event.sequence
                    for event in events
                ),
                default=(
                    checkpoint.last_sequence
                    if checkpoint
                    else None
                ),
            )
        )

        next_checkpoint = AuditCheckpoint(
            source_path=audit_path,
            file_device=metadata["device"],
            file_inode=metadata["inode"],
            offset=safe_offset,
            last_sequence=last_sequence,
            pending_data=pending_data,
        )

        return AuditCollectionResult(
            evidence=tuple(evidence),
            checkpoint=next_checkpoint,
        )

    def commit_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
    ) -> None:
        """
        Commit a checkpoint after evidence persistence succeeds.
        """

        self.checkpoint_store.save(
            checkpoint
        )

    # =======================================================================
    # COMPATIBILITY API
    # =======================================================================

    def collect(
        self,
        *,
        tenant: TenantContext,
        instance_name: str,
        audit_path: str = DEFAULT_AUDIT_PATH,
    ) -> AuditEvidence:
        """
        Compatibility method for existing capture code.

        New host-wide code should use collect_new().

        This method obtains new host audit evidence and returns a single
        aggregate AuditEvidence object for the requested tenant/instance.

        Important:

            The underlying acquisition remains host-wide.

        This method should eventually be removed once EvidenceCaptureService
        has been migrated to collect_new().
        """

        result = self.collect_new(
            audit_path=audit_path
        )

        matching = [
            evidence
            for evidence in result.evidence
            if (
                evidence.tenant_id
                == tenant.tenant_id
                and evidence.instance_name
                == instance_name
            )
        ]

        if not matching:
            raise CollectorError(
                "No new audit events found for "
                f"{tenant.platform_project_id}/"
                f"{instance_name}",
                source=self.source,
            )

        combined_raw = b"".join(
            evidence.raw_data
            for evidence in matching
        )

        sequences = [
            evidence.sequence_start
            for evidence in matching
            if evidence.sequence_start is not None
        ]

        return AuditEvidence(
            evidence_id=(
                self._make_batch_id(
                    tenant_id=tenant.tenant_id,
                    instance_name=instance_name,
                    raw_data=combined_raw,
                )
            ),
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
            acquisition_layer="host",
            acquired_from=self.host_id,
            attribution_method="incus_subject",
            collected_at=datetime.now(
                timezone.utc
            ),
            raw_data=combined_raw,
            sha256=self.hashing_service.sha256(
                combined_raw
            ),
            size_bytes=len(combined_raw),
            sequence_start=(
                min(sequences)
                if sequences
                else None
            ),
            sequence_end=(
                max(sequences)
                if sequences
                else None
            ),
        )

    # =======================================================================
    # INCREMENTAL PARSING
    # =======================================================================

    @classmethod
    def _parse_incremental_data(
        cls,
        raw_data: bytes,
    ) -> tuple[
        list[AuditEvent],
        bytes,
    ]:
        """
        Parse incremental native audit.log data.

        Native audit.log records are line-oriented.

        The final incomplete line is retained as pending data.

        Events are then grouped by audit serial number.

        The highest sequence is held back because auditd may still be
        appending additional records belonging to that event.
        """

        if not raw_data:
            return [], b""

        lines = raw_data.splitlines(
            keepends=True
        )

        complete_lines: list[bytes] = []
        pending_line = b""

        if lines:
            last_line = lines[-1]

            if not last_line.endswith(
                b"\n"
            ):
                pending_line = last_line
                lines = lines[:-1]

        for line in lines:
            line = line.strip()

            if not line:
                continue

            if b"msg=audit(" not in line:
                continue

            complete_lines.append(
                line + b"\n"
            )

        if pending_line:
            pending = pending_line
        else:
            pending = b""

        events = cls._group_records(
            complete_lines
        )

        if not events:
            return [], pending

        # ---------------------------------------------------------------
        # Hold the highest sequence.
        #
        # Auditd can still append records belonging to the newest event.
        # The next collection cycle will combine it with new bytes.
        # ---------------------------------------------------------------

        highest_sequence = max(
            event.sequence
            for event in events
        )

        complete_events: list[AuditEvent] = []
        highest_event: AuditEvent | None = None

        for event in events:
            if (
                event.sequence
                == highest_sequence
            ):
                highest_event = event
            else:
                complete_events.append(
                    event
                )

        if highest_event is not None:
            pending = (
                highest_event.raw_data
                + pending
            )

        return complete_events, pending

    @classmethod
    def _group_records(
        cls,
        records: list[bytes],
    ) -> list[AuditEvent]:
        """
        Group audit records by serial number.

        All records containing:

            msg=audit(...:<serial>)

        are considered part of the same logical event.
        """

        grouped: dict[
            int,
            list[bytes],
        ] = {}

        for record in records:
            sequence = (
                cls._extract_sequence(
                    record
                )
            )

            if sequence is None:
                continue

            grouped.setdefault(
                sequence,
                [],
            ).append(record)

        events: list[AuditEvent] = []

        for sequence in sorted(grouped):
            events.append(
                AuditEvent(
                    sequence=sequence,
                    raw_data=b"".join(
                        grouped[sequence]
                    ),
                )
            )

        return events

    # =======================================================================
    # EVIDENCE CONSTRUCTION
    # =======================================================================

    def _build_evidence(
        self,
        *,
        event: AuditEvent,
        attribution: AuditAttribution,
        audit_path: str,
    ) -> AuditEvidence:
        raw_data = event.raw_data

        evidence_hash = (
            self.hashing_service.sha256(
                raw_data
            )
        )

        tenant_id = (
            attribution.tenant_id
        )

        instance_name = (
            attribution.instance_id
        )

        if tenant_id is not None:
            scope = (
                f"{tenant_id}/"
                f"{instance_name}"
            )
        else:
            scope = self.host_id

        return AuditEvidence(
            evidence_id=(
                self._make_event_id(
                    host_id=self.host_id,
                    sequence=event.sequence,
                    raw_data=raw_data,
                )
            ),
            tenant_id=tenant_id,
            tenant_hash=None,
            project_id=tenant_id,
            instance_name=instance_name,
            scope=scope,
            source=self.source,
            source_path=audit_path,
            acquisition_layer="host",
            acquired_from=self.host_id,
            attribution_method=(
                attribution.method
            ),
            collected_at=datetime.now(
                timezone.utc
            ),
            raw_data=raw_data,
            sha256=evidence_hash,
            size_bytes=len(raw_data),
            sequence_start=event.sequence,
            sequence_end=event.sequence,
        )

    # =======================================================================
    # DETERMINISTIC ID
    # =======================================================================
    @staticmethod
    def _make_event_id(
        *,
        host_id: str,
        sequence: int,
        raw_data: bytes,
    ) -> str:
        """
        Produce deterministic identity for one host audit event.
        """

        digest = hashlib.sha256(
            raw_data
        ).hexdigest()

        return (
            f"auditd:"
            f"{sequence}:"
            f"{digest}"
        )

    @staticmethod
    def _make_batch_id(
        *,
        tenant_id: str,
        instance_name: str,
        raw_data: bytes,
    ) -> str:
        digest = hashlib.sha256(
            raw_data
        ).hexdigest()

        return (
            f"auditd-batch:"
            f"{tenant_id}:"
            f"{instance_name}:"
            f"{digest}"
        )

    # =======================================================================
    # HOST FILE ACCESS
    # =======================================================================

    def _stat_audit_file(
        self,
        audit_path: str,
    ) -> dict[str, int]:
        """
        Obtain device, inode and size for the host audit file.
        """

        try:
            result = self.executor.exec(
                command=[
                    "stat",
                    "-c",
                    "%d %i %s",
                    audit_path,
                ],
            )
        except Exception as exc:
            raise CollectorError(
                "Failed to stat host audit log",
                source=self.source,
            ) from exc

        if result.returncode != 0:
            stderr = (
                result.stderr.decode(
                    errors="replace"
                ).strip()
            )

            raise CollectorError(
                "Failed to stat host audit log"
                + (
                    f": {stderr}"
                    if stderr
                    else ""
                ),
                source=self.source,
            )

        try:
            device, inode, size = (
                int(value)
                for value in (
                    result.stdout.decode(
                        "utf-8"
                    ).strip().split()
                )
            )
        except (
            ValueError,
            UnicodeDecodeError,
        ) as exc:
            raise CollectorError(
                "Invalid audit log stat output",
                source=self.source,
            ) from exc

        return {
            "device": device,
            "inode": inode,
            "size": size,
        }

    def _read_audit_range(
        self,
        *,
        audit_path: str,
        offset: int,
        size: int,
    ) -> bytes:
        """
        Read a byte range from the host audit log.
        """

        if size <= 0:
            return b""

        try:
            result = self.executor.exec(
                command=[
                    "dd",
                    f"if={audit_path}",
                    "bs=1",
                    f"skip={offset}",
                    f"count={size}",
                    "status=none",
                ],
            )
        except Exception as exc:
            raise CollectorError(
                "Failed to read host audit log",
                source=self.source,
            ) from exc

        if result.returncode != 0:
            stderr = (
                result.stderr.decode(
                    errors="replace"
                ).strip()
            )

            raise CollectorError(
                "Failed to read host audit log"
                + (
                    f": {stderr}"
                    if stderr
                    else ""
                ),
                source=self.source,
            )

        return result.stdout

    # =======================================================================
    # CHECKPOINT HANDLING
    # =======================================================================

    @staticmethod
    def _calculate_start_offset(
        *,
        checkpoint: AuditCheckpoint | None,
        metadata: dict[str, int],
        audit_path: str,
    ) -> int:
        if checkpoint is None:
            return 0

        if checkpoint.source_path != audit_path:
            return 0

        same_file = (
            checkpoint.file_device
            == metadata["device"]
            and checkpoint.file_inode
            == metadata["inode"]
        )

        if not same_file:
            # Audit log rotation detected.
            return 0

        if metadata["size"] < checkpoint.offset:
            # File was truncated.
            return 0

        return checkpoint.offset

    # =======================================================================
    # VALIDATION
    # =======================================================================

    @staticmethod
    def _validate_audit_path(
        audit_path: str,
    ) -> None:
        if not audit_path.strip():
            raise ValueError(
                "audit_path must not be empty"
            )

        if not audit_path.startswith(
            "/"
        ):
            raise ValueError(
                "audit_path must be absolute"
            )

    # =======================================================================
    # LEGACY HELPERS
    # =======================================================================

    @staticmethod
    def _extract_sequence(
        record: bytes,
    ) -> int | None:
        match = _AUDIT_SEQUENCE_RE.search(
            record
        )

        if not match:
            return None

        return int(
            match.group(1)
        )

    @classmethod
    def _parse_events(
        cls,
        raw_data: bytes,
    ) -> list[AuditEvent]:
        """
        Backwards-compatible parser for existing tests.

        Unlike collect_new(), this parses an entire supplied byte string
        and does not use checkpointing.
        """

        records = []

        for line in raw_data.splitlines(
            keepends=True
        ):
            line = line.strip()

            if (
                line
                and b"msg=audit(" in line
            ):
                records.append(
                    line + b"\n"
                )

        return cls._group_records(
            records
        )

    @staticmethod
    def _extract_sequence_range(
        raw_data: bytes,
    ) -> tuple[
        int | None,
        int | None,
    ]:
        sequences = [
            int(match.group(1))
            for match in (
                _AUDIT_SEQUENCE_RE.finditer(
                    raw_data
                )
            )
        ]

        if not sequences:
            return None, None

        return (
            min(sequences),
            max(sequences),
        )