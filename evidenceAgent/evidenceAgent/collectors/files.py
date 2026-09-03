from __future__ import annotations

import uuid
from pathlib import Path
from typing import Iterable

from evidenceAgent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


class FileCollector:
    """
    Collects filesystem create/delete events from one or more directories.

    The collector maintains an in-memory snapshot for each configured path.
    Each call to collect() compares the current filesystem state with the
    previous snapshot and emits EvidenceEvent objects for newly created or
    deleted files.
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

        # Normalize all configured paths to strings.
        #
        # agent.py currently passes:
        #     [config.watched_directory]
        #
        # so this also works when watched_directory is a Path object.
        self.paths: tuple[str, ...] = tuple(
            str(path)
            for path in paths
        )

        self.snapshots: dict[str, set[str]] = {}

        self._initialize()

    def _initialize(self) -> None:
        """
        Create the initial filesystem snapshot for each configured path.
        """

        for root in self.paths:
            self.snapshots[root] = self._snapshot(root)

    def _snapshot(
        self,
        root: str,
    ) -> set[str]:
        """
        Return a set containing all files currently present below root.

        Missing directories are treated as empty directories.

        Permission errors are ignored so that one inaccessible path does
        not stop the entire evidence collection cycle.
        """

        path = Path(root)

        if not path.exists():
            return set()

        result: set[str] = set()

        try:
            for item in path.rglob("*"):
                if item.is_file():
                    result.add(str(item))

        except PermissionError:
            pass

        return result

    def collect(self) -> list[EvidenceEvent]:
        """
        Detect filesystem changes since the previous collection cycle.

        Returns:
            A list of EvidenceEvent objects representing file creations
            and deletions.
        """

        events: list[EvidenceEvent] = []

        for root in self.paths:
            previous = self.snapshots.get(
                root,
                set(),
            )

            current = self._snapshot(root)

            created = current - previous
            deleted = previous - current

            for path in sorted(created):
                events.append(
                    self._event(
                        event_type=EventType.FILE_CREATE,
                        path=path,
                    )
                )

            for path in sorted(deleted):
                events.append(
                    self._event(
                        event_type=EventType.FILE_DELETE,
                        path=path,
                    )
                )

            # Update the snapshot after processing the differences.
            self.snapshots[root] = current

        return events

    def _event(
        self,
        *,
        event_type: EventType,
        path: str,
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
            details={
                "path": path,
            },
            raw_data=raw,
        )

        self.state.set_sequence(sequence)

        return event