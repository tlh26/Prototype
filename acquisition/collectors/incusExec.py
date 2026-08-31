# acquisition/collectors/incusExec.py

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


class IncusExecutionError(RuntimeError):
    """Raised when an Incus command fails."""


@dataclass(frozen=True)
class IncusCommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class IncusExecutor:
    """
    Executes commands inside Incus instances.

    The executor returns raw bytes so that acquisition collectors
    can preserve evidence without modifying the source data.
    """

    def __init__(
        self,
        incus_binary: str = "incus",
    ) -> None:
        self.incus_binary = incus_binary

    def exec(
        self,
        *,
        project: str,
        instance: str,
        command: Sequence[str],
        timeout: int = 60,
    ) -> IncusCommandResult:

        cmd = [
            self.incus_binary,
            "exec",
            instance,
            "--project",
            project,
            "--",
            *command,
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            raise IncusExecutionError(
                "Incus command failed "
                f"(project={project}, "
                f"instance={instance}, "
                f"returncode={result.returncode}): "
                f"{result.stderr.decode(errors='replace')}"
            )

        return IncusCommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )