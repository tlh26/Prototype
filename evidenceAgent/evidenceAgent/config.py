from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    tenant_id: str
    instance_name: str
    agent_id: str

    central_url: str
    api_key: str

    auth_log: Path
    access_log: Path
    watched_directory: Path

    state_directory: Path
    spool_directory: Path

    interval: int = 10

    @classmethod
    def from_environment(cls) -> "AgentConfig":
        def required(name: str) -> str:
            value = os.getenv(name)

            if not value:
                raise RuntimeError(f"Missing environment variable: {name}")

            return value

        return cls(
            tenant_id=required("EVIDENCE_TENANT_ID"),
            instance_name=required("EVIDENCE_INSTANCE_NAME"),
            agent_id=required("EVIDENCE_AGENT_ID"),
            central_url=required("EVIDENCE_CENTRAL_URL"),
            api_key=required("EVIDENCE_API_KEY"),
            auth_log=Path(
                os.getenv(
                    "EVIDENCE_AUTH_LOG",
                    "/var/log/auth.log",
                )
            ),
            access_log=Path(
                os.getenv(
                    "EVIDENCE_ACCESS_LOG",
                    "/var/log/nginx/access.log",
                )
            ),
            watched_directory=Path(
                os.getenv(
                    "EVIDENCE_WATCHED_DIRECTORY",
                    "/tmp/evidence",
                )
            ),
            state_directory=Path(
                os.getenv(
                    "EVIDENCE_STATE_DIRECTORY",
                    "/var/lib/evidence-agent",
                )
            ),
            spool_directory=Path(
                os.getenv(
                    "EVIDENCE_SPOOL_DIRECTORY",
                    "/var/lib/evidence-agent/spool",
                )
            ),
            interval=int(
                os.getenv(
                    "EVIDENCE_INTERVAL",
                    "10",
                )
            ),
        )
