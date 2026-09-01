from __future__ import annotations

import re
import uuid
from pathlib import Path

from evidenceAgent.models import (
    EvidenceEvent,
    EvidenceType,
    EventType,
)


class AuthenticationCollector:

    PATTERNS = [
        (
            re.compile(
                r"Accepted .* for (\S+) from (\S+)"
            ),
            EventType.LOGIN_SUCCESS,
        ),
        (
            re.compile(
                r"Failed .* for (?:invalid user )?(\S+) from (\S+)"
            ),
            EventType.LOGIN_FAILURE,
        ),
        (
            re.compile(
                r"session opened for user (\S+)"
            ),
            EventType.SESSION_CREATED,
        ),
        (
            re.compile(
                r"session closed for user (\S+)"
            ),
            EventType.SESSION_TERMINATED,
        ),
    ]

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

            text = line.decode(
                "utf-8",
                errors="replace",
            )

            for pattern, event_type in self.PATTERNS:

                match = pattern.search(text)

                if not match:
                    continue

                actor = match.group(1)

                event = EvidenceEvent.now(
                    event_id=str(uuid.uuid4()),
                    tenant_id=self.tenant_id,
                    instance_name=self.instance_name,
                    evidence_type=EvidenceType.AUTHENTICATION,
                    event_type=event_type,
                    sequence=self.state.get_sequence() + 1,
                    agent_id=self.agent_id,
                    source="auth.log",
                    source_path=str(self.path),
                    actor=actor,
                    resource=match.group(2)
                    if match.lastindex and match.lastindex >= 2
                    else None,
                    details={
                        "raw_line": text,
                    },
                    raw_data=line + b"\n",
                )

                events.append(event)

                self.state.set_sequence(
                    event.sequence
                )

                break

        return events