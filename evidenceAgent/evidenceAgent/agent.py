from __future__ import annotations

import time

from .client import CentralEvidenceClient
from .collectors.access import AccessCollector
from .collectors.authentication import (
    AuthenticationCollector,
)
from .collectors.files import FileCollector
from .config import AgentConfig
from .models import EvidenceEvent
from .spool import EvidenceSpool
from .state import AgentState


class EvidenceAgent:

    def __init__(
        self,
        config: AgentConfig,
    ):
        self.config = config

        self.state = AgentState(config.state_directory)

        self.spool = EvidenceSpool(f"{config.state_directory}/spool")

        self.client = CentralEvidenceClient(
            base_url=config.central_url,
            api_key=config.api_key,
        )

        self.authentication = AuthenticationCollector(
            tenant_id=config.tenant_id,
            instance_name=config.instance_name,
            agent_id=config.agent_id,
            path=config.auth_log,
            state=self.state,
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
            paths=[config.watched_directory],
            state=self.state,
        )

    def collect_once(self):
        """
        Run one evidence collection cycle and then attempt to
        drain previously spooled evidence.
        """

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

        self.retry_spool()

    def _process(
        self,
        event: EvidenceEvent,
    ):
        """
        Persist an event locally before attempting transmission.

        This ensures that an event is never lost simply because
        Central is temporarily unavailable.
        """

        path = self.spool.store(event)

        try:

            self.client.submit(event)

            self.spool.remove(path)

            print(f"[agent] submitted evidence: " f"{event.event_id}")

        except Exception as exc:

            print(
                f"[agent] central storage unavailable; "
                f"evidence spooled: {event.event_id}: {exc}"
            )

    def retry_spool(self):
        """
        Attempt to submit all locally spooled evidence.

        A spool entry is removed only after Central successfully
        acknowledges the event.

        If Central is still unavailable, the entry remains on disk
        and will be retried during the next collection cycle.
        """

        pending = self.spool.pending()

        if not pending:
            return

        print(f"[agent] retrying {len(pending)} " f"spooled evidence event(s)")

        for path in pending:

            try:

                event = self.spool.load(path)

                if not isinstance(event, EvidenceEvent):
                    raise TypeError(
                        f"Expected EvidenceEvent in instance spool, "
                        f"got {type(event).__name__}"
                    )

                self.client.submit(event)

                self.spool.remove(path)

                print(f"[agent] drained spool: " f"{event.event_id}")

            except Exception as exc:

                print(f"[agent] spool retry failed: " f"{path.name}: {exc}")

    def run(self):

        print(
            f"[agent] started: "
            f"{self.config.tenant_id}/"
            f"{self.config.instance_name}"
        )

        while True:

            self.collect_once()

            time.sleep(self.config.interval)
