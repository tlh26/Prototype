from __future__ import annotations

from dataclasses import dataclass

from acquisition.collectors.incusExec import IncusExecutor


@dataclass(frozen=True)
class InstanceTarget:
    project: str
    instance: str


class IncusInventory:

    def __init__(
        self,
        executor: IncusExecutor,
    ) -> None:
        self.executor = executor

    def list_instances(
        self,
        project: str,
    ) -> list[str]:

        result = self.executor.exec(
            project=project,
            instance="",  # see note below
            command=[
                "true",
            ],
        )
