from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentConfig:

    tenant_id: str
    instance_name: str
    agent_id: str

    central_url: str

    api_key: str

    state_dir: str = "/var/lib/evidence-agent"

    poll_interval: float = 2.0

    auth_log: str = "/var/log/auth.log"

    access_log: str = "/var/log/nginx/access.log"

    watch_paths: tuple[str, ...] = (
        "/etc",
        "/var/www",
    )

    @classmethod
    def from_environment(cls) -> "AgentConfig":

        required = [
            "EVIDENCE_TENANT_ID",
            "EVIDENCE_INSTANCE_NAME",
            "EVIDENCE_AGENT_ID",
            "EVIDENCE_CENTRAL_URL",
            "EVIDENCE_API_KEY",
        ]

        values = {}

        for name in required:
            value = os.getenv(name)

            if not value:
                raise RuntimeError(
                    f"Missing environment variable: {name}"
                )

            values[name] = value

        return cls(
            tenant_id=values["EVIDENCE_TENANT_ID"],
            instance_name=values["EVIDENCE_INSTANCE_NAME"],
            agent_id=values["EVIDENCE_AGENT_ID"],
            central_url=values["EVIDENCE_CENTRAL_URL"],
            api_key=values["EVIDENCE_API_KEY"],
            state_dir=os.getenv(
            "EVIDENCE_STATE_DIR",
            "./data/evidence-agent",
    ),
)