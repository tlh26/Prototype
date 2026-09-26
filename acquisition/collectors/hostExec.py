# acquisition/collectors/hostExec.py

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class HostCommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class HostExecutor:

    def __init__(
        self,
        *,
        use_sudo: bool = False,
    ) -> None:
        self.use_sudo = use_sudo

    def exec(
        self,
        *,
        command: list[str],
    ) -> HostCommandResult:

        effective_command = list(command)

        if self.use_sudo:
            effective_command = [
                "/usr/bin/sudo",
                "-n",
                *effective_command,
            ]

        result = subprocess.run(
            effective_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        return HostCommandResult(
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
