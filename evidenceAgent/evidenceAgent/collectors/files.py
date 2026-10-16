# evidenceAgent/evidenceAgent/collectors/files.py

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Iterable

from ..models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


# A file fingerprint consists of:
# (file size, modification time in nanoseconds, SHA-256 content hash)
FileFingerprint = tuple[int, int, str]


class FileCollector:
    """
    Collect filesystem create, modify, and delete events.

    Each configured root has an in-memory snapshot mapping file paths
    to fingerprints. A fingerprint includes file size, modification
    time, and SHA-256 content hash.

    Changes are detected by comparing the current snapshot with the
    previous snapshot.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        instance_name: str,
        agent_id: str,
        paths: Iterable[str | Path],
        state,
    ):
        self.tenant_id = tenant_id
        self.instance_name = instance_name
        self.agent_id = agent_id
        self.state = state

        # Normalize configured paths to strings.
        self.paths: tuple[str, ...] = tuple(
            str(path) for path in paths
        )

        # Each snapshot maps a file path to its fingerprint.
        self.snapshots: dict[
            str, dict[str, FileFingerprint]
        ] = {}

        self._initialize()

    def _initialize(self) -> None:
        """
        Establish the initial snapshot for each configured root.

        Existing files are treated as the baseline. They do not
        generate creation events during initialization.
        """
        for root in self.paths:
            self.snapshots[root] = self._snapshot(root)

    @staticmethod
    def _fingerprint(
        path: Path,
    ) -> FileFingerprint | None:
        """
        Calculate a fingerprint for a file.

        Returns None if the file cannot be read or inspected.

        The metadata is checked before and after hashing to reduce
        the chance of accepting a fingerprint for a file that was
        changing while it was being read.
        """
        try:
            before = path.stat()

            if not path.is_file():
                return None

            digest = hashlib.sha256()

            with path.open("rb") as file:
                for chunk in iter(
                    lambda: file.read(1024 * 1024),
                    b"",
                ):
                    digest.update(chunk)

            after = path.stat()

            # Retry on a later collection cycle if metadata changed
            # while the file was being read.
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                return None

            return (
                after.st_size,
                after.st_mtime_ns,
                digest.hexdigest(),
            )

        except (OSError, PermissionError):
            # Do not let one inaccessible file stop collection.
            return None

    def _snapshot(
        self,
        root: str,
    ) -> dict[str, FileFingerprint]:
        """
        Return fingerprints for files below a configured root.

        Missing or inaccessible roots produce an empty snapshot.
        Files that cannot be fingerprinted are omitted.
        """
        path = Path(root)

        if not path.exists() or not path.is_dir():
            return {}

        result: dict[str, FileFingerprint] = {}

        try:
            for item in path.rglob("*"):
                try:
                    if not item.is_file():
                        continue

                    fingerprint = self._fingerprint(item)

                    if fingerprint is not None:
                        result[str(item)] = fingerprint

                except OSError:
                    # Skip an individual problematic entry.
                    continue

        except OSError:
            # Directory traversal may fail because of permissions
            # or filesystem errors.
            pass

        return result

    def collect(self) -> list[EvidenceEvent]:
        """
        Detect filesystem changes since the previous collection.

        Returns:
            Evidence events representing file creation,
            modification, and deletion.
        """
        events: list[EvidenceEvent] = []

        for root in self.paths:
            previous = self.snapshots.get(root, {})
            current = self._snapshot(root)

            previous_paths = set(previous)
            current_paths = set(current)

            created = current_paths - previous_paths
            deleted = previous_paths - current_paths
            common = previous_paths & current_paths

            # Detect newly created files.
            for path in sorted(created):
                fingerprint = current[path]

                events.append(
                    self._event(
                        event_type=EventType.FILE_CREATE,
                        path=path,
                        details={
                            "path": path,
                            "size": fingerprint[0],
                            "mtime_ns": fingerprint[1],
                            "sha256": fingerprint[2],
                        },
                    )
                )

            # Detect modified files.
            for path in sorted(common):
                old_fingerprint = previous[path]
                new_fingerprint = current[path]

                if old_fingerprint != new_fingerprint:
                    events.append(
                        self._event(
                            event_type=EventType.FILE_MODIFY,
                            path=path,
                            details={
                                "path": path,
                                "previous_size": old_fingerprint[0],
                                "current_size": new_fingerprint[0],
                                "previous_mtime_ns": old_fingerprint[1],
                                "current_mtime_ns": new_fingerprint[1],
                                "previous_sha256": old_fingerprint[2],
                                "current_sha256": new_fingerprint[2],
                            },
                        )
                    )

            # Detect deleted files.
            for path in sorted(deleted):
                fingerprint = previous[path]

                events.append(
                    self._event(
                        event_type=EventType.FILE_DELETE,
                        path=path,
                        details={
                            "path": path,
                            "previous_size": fingerprint[0],
                            "previous_mtime_ns": fingerprint[1],
                            "previous_sha256": fingerprint[2],
                        },
                    )
                )

            # Save the current snapshot for the next cycle.
            self.snapshots[root] = current

        return events

    def _event(
        self,
        *,
        event_type: EventType,
        path: str,
        details: dict | None = None,
    ) -> EvidenceEvent:
        """
        Create an EvidenceEvent for a filesystem change.
        """
        raw = path.encode("utf-8")

        sequence = self.state.get_sequence() + 1

        event = EvidenceEvent.now(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            instance_name=self.instance_name,
            evidence_type=EvidenceType.FILE,
            event_type=event_type,
            sequence=sequence,
            agent_id=self.agent_id,
            source="filesystem",
            source_path=path,
            resource=path,
            details=details or {"path": path},
            raw_data=raw,
        )

        self.state.set_sequence(sequence)

        return event