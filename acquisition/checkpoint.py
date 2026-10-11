from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuditCheckpoint:
    """
    Persistent cursor for incremental host audit acquisition.

    The source file identity is:

        source_path + file_device + file_inode

    These values must all refer to the same physical audit-log file.

    offset:
        Byte offset up to which data has been safely processed.

    last_sequence:
        Highest audit serial successfully persisted.

    pending_data:
        Raw bytes belonging to the current source file that are not
        yet safe to process as a complete event.
    """

    source_path: str
    file_device: int
    file_inode: int
    offset: int
    last_sequence: int | None = None
    pending_data: bytes = b""

    def to_dict(self) -> dict[str, object]:
        return {
            "source_path": self.source_path,
            "file_device": self.file_device,
            "file_inode": self.file_inode,
            "offset": self.offset,
            "last_sequence": self.last_sequence,
            "pending_data": base64.b64encode(self.pending_data).decode("ascii"),
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object],
    ) -> "AuditCheckpoint":
        encoded_pending = str(data.get("pending_data", ""))

        if encoded_pending:
            pending_data = base64.b64decode(
                encoded_pending,
                validate=True,
            )
        else:
            pending_data = b""

        return cls(
            source_path=str(data["source_path"]),
            file_device=int(data["file_device"]),
            file_inode=int(data["file_inode"]),
            offset=int(data["offset"]),
            last_sequence=(
                int(data["last_sequence"])
                if data.get("last_sequence") is not None
                else None
            ),
            pending_data=pending_data,
        )

    def matches_source(
        self,
        *,
        source_path: str,
        file_device: int,
        file_inode: int,
    ) -> bool:
        """
        Return True only when the checkpoint refers to the same
        physical source file.
        """

        return (
            self.source_path == str(Path(source_path).resolve())
            and self.file_device == file_device
            and self.file_inode == file_inode
        )


class CheckpointStore:
    """
    Atomic JSON checkpoint storage.

    This is operational state, not forensic evidence.
    """

    def __init__(
        self,
        path: str | Path,
    ) -> None:
        self.path = Path(path)

    def load(self) -> AuditCheckpoint | None:
        if not self.path.exists():
            return None

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = json.load(handle)

        return AuditCheckpoint.from_dict(data)

    def save(
        self,
        checkpoint: AuditCheckpoint,
    ) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, temporary_path = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump(
                    checkpoint.to_dict(),
                    handle,
                    indent=2,
                    sort_keys=True,
                )

                handle.flush()
                os.fsync(handle.fileno())

            os.replace(
                temporary_path,
                self.path,
            )

        finally:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
