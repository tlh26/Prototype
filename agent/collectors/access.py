from __future__ import annotations

import re
import uuid
from pathlib import Path

from agent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


class AccessCollector:

    METHOD_EVENTS = {
        "GET": EventType.RESOURCE_READ,
        "POST": EventType.RESOURCE_CREATE,
        "PUT": EventType.RESOURCE_UPDATE,
        "PATCH": EventType.RESOURCE_UPDATE,
        "DELETE": EventType.RESOURCE_DELETE,
    }

    LOG_PATTERN = re.compile(
        rb'(\S+) - (\S+) \[(.*?)\] '
        rb'"(\S+) (\S+) ([^"]+)" (\d+)'
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        instance_name: str,
        agent_id: str,
        path: str,
        state,
    ):

        self.tenant_id = tenant_id
        self.instance_name = instance_name
        self.agent_id = agent_id
        self.path = Path(path)
        self.state = state
        self.offset = 0

    def collect(self) -> list[EvidenceEvent]:

        if not self.path.exists():
            return []

        events = []

        with self.path.open(
            "rb"
        ) as handle:

            handle.seek(
                self.offset
            )

            data = handle.read()

            self.offset = handle.tell()

        for line in data.splitlines():

            match = self.LOG_PATTERN.search(
                line
            )

            if not match:
                continue

            actor = match.group(1).decode(
                errors="replace"
            )

            method = match.group(4).decode(
                errors="replace"
            )

            resource = match.group(5).decode(
                errors="replace"
            )

            event_type = self.METHOD_EVENTS.get(
                method,
                EventType.RESOURCE_ACCESS,
            )

            event = EvidenceEvent.now(
                event_id=str(uuid.uuid4()),
                tenant_id=self.tenant_id,
                instance_name=self.instance_name,
                evidence_type=EvidenceType.TRACE,
                event_type=event_type,
                sequence=self.state.get_sequence() + 1,
                agent_id=self.agent_id,
                source="nginx",
                source_path=str(self.path),
                actor=actor,
                resource=resource,
                details={
                    "method": method,
                    "status": int(
                        match.group(7)
                    ),
                    "raw_line": line.decode(
                        errors="replace"
                    ),
                },
                raw_data=line + b"\n",
            )

            events.append(event)

            self.state.set_sequence(
                event.sequence
            )

        return events