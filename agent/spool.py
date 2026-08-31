from __future__ import annotations

import json
from pathlib import Path

from agent.models import EvidenceEvent


class EvidenceSpool:

    def __init__(
        self,
        directory: str,
    ):

        self.directory = Path(directory)

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def store(
        self,
        event: EvidenceEvent,
    ) -> Path:

        path = (
            self.directory
            / f"{event.sequence:020d}_{event.event_id}.json"
        )

        payload = event.model_dump()

        payload["timestamp"] = (
            event.timestamp.isoformat()
        )

        payload["created_at"] = (
            event.created_at.isoformat()
        )

        payload["raw_data"] = (
            event.raw_data.decode(
                "utf-8",
                errors="replace",
            )
        )

        path.write_text(
            json.dumps(
                payload,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return path

    def pending(self) -> list[Path]:

        return sorted(
            self.directory.glob(
                "*.json"
            )
        )

    def remove(
        self,
        path: Path,
    ) -> None:

        path.unlink(
            missing_ok=True
        )