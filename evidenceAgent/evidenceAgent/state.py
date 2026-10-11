from __future__ import annotations

import json
from pathlib import Path
from threading import Lock


class AgentState:

    def __init__(self, directory: str):

        self.directory = Path(directory)

        self.directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.path = self.directory / "state.json"

        self._lock = Lock()

        if not self.path.exists():
            self._write({"sequence": 0})

    def _read(self) -> dict:

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as handle:

            return json.load(handle)

    def _write(self, state: dict) -> None:

        temporary = self.path.with_suffix(".tmp")

        with temporary.open(
            "w",
            encoding="utf-8",
        ) as handle:

            json.dump(
                state,
                handle,
                indent=2,
            )

        temporary.replace(self.path)

    def get_sequence(self) -> int:

        with self._lock:
            return int(self._read()["sequence"])

    def set_sequence(
        self,
        sequence: int,
    ) -> None:

        with self._lock:

            current = int(self._read()["sequence"])

            if sequence < current:
                raise ValueError("Agent sequence cannot move backwards")

            self._write({"sequence": sequence})
