from __future__ import annotations

import time

from agent.client import CentralEvidenceClient
from agent.collectors.access import AccessCollector
from agent.collectors.authentication import (
    AuthenticationCollector,
)
from agent.collectors.files import FileCollector
from agent.config import AgentConfig
from agent.models import EvidenceEvent
from agent.spool import EvidenceSpool
from agent.state import AgentState


class EvidenceAgent:

    def __init__(
        self,
        config: AgentConfig,
    ):

        self.config = config

        self.state = AgentState(
            config.state_dir
        )

        self.spool = EvidenceSpool(
            f"{config.state_dir}/spool"
        )

        self.client = CentralEvidenceClient(
            base_url=config.central_url,
            api_key=config.api_key,
        )

        self.authentication = (
            AuthenticationCollector(
                tenant_id=config.tenant_id,
                instance_name=config.instance_name,
                agent_id=config.agent_id,
                path=config.auth_log,
                state=self.state,
            )
        )

        self.access = AccessCollector(
            tenant_id=config.tenant_id,
            instance_name=config.instance_name,
            agent_id=config.agent_id,
            path=config.access_log,
            state=self.state,
        )

        self.files = FileCollector(
            tenant_id=config.tenant_id,
            instance_name=config.instance_name,
            agent_id=config.agent_id,
            paths=config.watch_paths,
            state=self.state,
        )

    def collect_once(self):

        collectors = [
            self.authentication,
            self.access,
            self.files,
        ]

        for collector in collectors:

            try:

                events = collector.collect()

                for event in events:
                    self._process(event)

            except Exception as exc:

                print(
                    f"[agent] collector failure: "
                    f"{collector.__class__.__name__}: {exc}"
                )

        self._retry_spool()

    def _process(
        self,
        event: EvidenceEvent,
    ):

        path = self.spool.store(
            event
        )

        try:

            self.client.submit(
                event
            )

            self.spool.remove(
                path
            )

        except Exception as exc:

            print(
                f"[agent] central storage unavailable: "
                f"{exc}"
            )

    def _retry_spool(self):

        for path in self.spool.pending():

            try:

                import json

                payload = json.loads(
                    path.read_text(
                        encoding="utf-8"
                    )
                )

                # For a production implementation,
                # deserialize into EvidenceEvent.
                # This prototype leaves the original
                # spool entry until the server acknowledges
                # the event.

                print(
                    f"[agent] pending evidence: {path}"
                )

            except Exception as exc:

                print(
                    f"[agent] spool error: {exc}"
                )

    def run(self):

        print(
            f"[agent] started: "
            f"{self.config.tenant_id}/"
            f"{self.config.instance_name}"
        )

        while True:

            self.collect_once()

            time.sleep(
                self.config.poll_interval
            )