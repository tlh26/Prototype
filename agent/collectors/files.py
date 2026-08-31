from __future__ import annotations

import uuid
from pathlib import Path

from agent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


class FileCollector:

    def __init__(
        self,
        *,
        tenant_id: str,
        instance_name: str,
        agent_id: str,
        paths: tuple[str, ...],
        state,
    ):

        self.tenant_id = tenant_id
        self.instance_name = instance_name
        self.agent_id = agent_id
        self.paths = paths
        self.state = state

        self.snapshots: dict[str, set[str]] = {}

        self._initialize()

    def _initialize(self):

        for root in self.paths:

            self.snapshots[root] = self._snapshot(
                root
            )

    def _snapshot(
        self,
        root: str,
    ) -> set[str]:

        path = Path(root)

        if not path.exists():
            return set()

        result = set()

        try:

            for item in path.rglob("*"):

                if item.is_file():
                    result.add(
                        str(item)
                    )

        except PermissionError:
            pass

        return result

    def collect(self) -> list[EvidenceEvent]:

        events = []

        for root in self.paths:

            previous = self.snapshots.get(
                root,
                set(),
            )

            current = self._snapshot(
                root
            )

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

            self.snapshots[root] = current

        return events

    def _event(
        self,
        *,
        event_type: EventType,
        path: str,
    ) -> EvidenceEvent:

        raw = path.encode(
            "utf-8"
        )

        event = EvidenceEvent.now(
            event_id=str(uuid.uuid4()),
            tenant_id=self.tenant_id,
            instance_name=self.instance_name,
            evidence_type=EvidenceType.FILE,
            event_type=event_type,
            sequence=self.state.get_sequence() + 1,
            agent_id=self.agent_id,
            source="filesystem",
            source_path=path,
            resource=path,
            details={
                "path": path,
            },
            raw_data=raw,
        )

        self.state.set_sequence(
            event.sequence
        )

        return event