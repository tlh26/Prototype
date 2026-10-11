from __future__ import annotations

import json
import os
from pathlib import Path

from .models import EvidenceEvent
from .transportModels import EvidenceBatch


class EvidenceSpool:
    """
    Durable local queue for evidence that could not be
    submitted to Central.

    InstanceAgent entries contain one EvidenceEvent.
    HostAgent entries contain one EvidenceBatch.

    Entries remain on disk until Central successfully
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
        item: EvidenceEvent | EvidenceBatch,
    ) -> Path:
        """
        Persist either an instance EvidenceEvent or a host
        EvidenceBatch.
        """

        if isinstance(item, EvidenceEvent):
            payload = item.model_dump(mode="json")
            path = self.directory / self._event_filename(item)

        elif isinstance(item, EvidenceBatch):
            payload = item.model_dump(mode="json")
            path = self.directory / self._batch_filename(item)

        else:
            raise TypeError(f"Unsupported spool item type: " f"{type(item).__name__}")

        temporary_path = path.with_suffix(".tmp")

        data = json.dumps(
            payload,
            sort_keys=True,
        )

        with temporary_path.open(
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        temporary_path.replace(path)

        return path

    def _event_filename(
        self,
        event: EvidenceEvent,
    ) -> str:
        return f"{event.sequence:020d}_" f"{event.event_id}.json"

    def _batch_filename(
        self,
        batch: EvidenceBatch,
    ) -> str:
        if batch.evidence:
            sequence = min(
                (
                    envelope.sequence_start
                    for envelope in batch.evidence
                    if envelope.sequence_start is not None
                ),
                default=0,
            )
        else:
            sequence = 0

        return f"{sequence:020d}_" f"{batch.agent_id}.json"

    def pending(self) -> list[Path]:
        return sorted(self.directory.glob("*.json"))

    def load(
        self,
        path: Path,
    ) -> EvidenceEvent | EvidenceBatch:
        """
        Deserialize a spool entry.

        The payload shape determines whether the entry is an
        instance EvidenceEvent or a host EvidenceBatch.
        """

        payload = json.loads(path.read_text(encoding="utf-8"))

        if "evidence" in payload:
            return EvidenceBatch.model_validate(payload)

        return EvidenceEvent.model_validate(payload)

    def remove(
        self,
        path: Path,
    ) -> None:
        path.unlink(missing_ok=True)
