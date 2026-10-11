from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HostAgentConfig:
    agent_id: str

    central_url: str
    api_key: str

    audit_path: Path

    state_directory: Path
    checkpoint_path: Path
    spool_directory: Path

    interval: int = 10

    @classmethod
    def from_environment(cls) -> "HostAgentConfig":
        def required(name: str) -> str:
            value = os.getenv(name)

            if not value:
                raise RuntimeError(f"Missing environment variable: {name}")

            return value

        state_directory = Path(
            os.getenv(
                "EVIDENCE_STATE_DIRECTORY",
                "/var/lib/evidence-agent",
            )
        ).expanduser()

        checkpoint_path = Path(
            os.getenv(
                "EVIDENCE_HOST_CHECKPOINT_PATH",
                str(state_directory / "host-audit-checkpoint.json"),
            )
        ).expanduser()

        spool_directory = Path(
            os.getenv(
                "EVIDENCE_HOST_SPOOL_DIRECTORY",
                str(state_directory / "host-spool"),
            )
        ).expanduser()

        return cls(
            agent_id=required("EVIDENCE_AGENT_ID"),
            central_url=required("EVIDENCE_CENTRAL_URL"),
            api_key=required("EVIDENCE_API_KEY"),
            audit_path=Path(
                os.getenv(
                    "EVIDENCE_AUDIT_PATH",
                    "/var/log/audit/audit.log",
                )
            ).expanduser(),
            state_directory=state_directory,
            checkpoint_path=checkpoint_path,
            spool_directory=spool_directory,
            interval=int(
                os.getenv(
                    "EVIDENCE_INTERVAL",
                    "10",
                )
            ),
        )
