from __future__ import annotations

import base64
import json
from pathlib import Path

from evidenceAgent.models import EvidenceEvent


class EvidenceSpool:
    """
    Durable local queue for evidence events that could not be
    submitted to the Central API.

    Events remain on disk until the Central API successfully
    acknowledges them.
    """

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
        """
        Persist an evidence event to the local spool.

        raw_data is Base64 encoded so the original bytes are preserved
        exactly, including arbitrary binary evidence.
        """

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

        payload["raw_data"] = base64.b64encode(
            event.raw_data
        ).decode("ascii")

        path.write_text(
            json.dumps(
                payload,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        return path

    def pending(self) -> list[Path]:
        """
        Return all pending spool entries in sequence order.
        """

        return sorted(
            self.directory.glob("*.json")
        )

    def load(
        self,
        path: Path,
    ) -> EvidenceEvent:
        """
        Load and deserialize a spooled evidence event.
        """

        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        payload["raw_data"] = base64.b64decode(
            payload["raw_data"],
            validate=True,
        )

        return EvidenceEvent.model_validate(
            payload
        )

    def remove(
        self,
        path: Path,
    ) -> None:
        """
        Remove a spool entry after successful submission.
        """

        path.unlink(
            missing_ok=True
        )