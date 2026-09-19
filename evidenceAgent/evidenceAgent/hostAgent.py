from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .client import CentralEvidenceClient
from .hostConfig import HostAgentConfig
from .serialization import audit_evidence_to_envelope
from .spool import EvidenceSpool
from .transportModels import EvidenceBatch


if TYPE_CHECKING:
    from acquisition.checkpoint import AuditCheckpoint
    from acquisition.collectors.audit import AuditCollector


@dataclass(frozen=True)
class HostCollectionResult:
    """
    Result of one host audit collection cycle.

    The checkpoint is returned to the caller but is deliberately
    not committed here. It should only be committed after the
    corresponding EvidenceBatch has been successfully delivered
    to Central.
    """

    batch: EvidenceBatch
    checkpoint: AuditCheckpoint


class HostEvidenceAgent:
    """
    Host-side evidence agent.

    Responsibilities:
    - Collect incremental audit evidence from the Incus host.
    - Convert acquired audit evidence into transport envelopes.
    - Persist batches to the local spool before transmission.
    - Submit batches to Central.
    - Remove spool entries only after successful delivery.
    - Retry previously spooled batches after an outage.

    The agent does NOT commit the audit checkpoint itself. Checkpoint
    commitment is controlled by the runtime so that evidence is never
    acknowledged as processed before successful delivery.

    The host-side acquisition package is intentionally not imported
    when this module is loaded. It is supplied by the host runtime
    when HostEvidenceAgent is actually constructed.
    """

    def __init__(
        self,
        *,
        config: HostAgentConfig,
        collector: AuditCollector,
    ) -> None:

        self.config = config
        self.collector = collector

        self.spool = EvidenceSpool(
            str(config.spool_directory)
        )

        self.client = CentralEvidenceClient(
            base_url=config.central_url,
            api_key=config.api_key,
        )

    def collect(self) -> HostCollectionResult:
        """
        Collect new audit evidence from the Incus host.

        The collector operates incrementally using its persisted
        checkpoint. The returned checkpoint is NOT committed here.
        """

        result = self.collector.collect_new(
            audit_path=str(
                self.config.audit_path
            )
        )

        envelopes = tuple(
            audit_evidence_to_envelope(
                evidence
            )
            for evidence in result.evidence
        )

        batch = EvidenceBatch(
            agent_id=self.config.agent_id,
            evidence=envelopes,
        )

        return HostCollectionResult(
            batch=batch,
            checkpoint=result.checkpoint,
        )

    def process_batch(
        self,
        batch: EvidenceBatch,
    ) -> None:
        """
        Persist and deliver an evidence batch.

        Delivery order:

            1. Write batch to spool.
            2. Submit batch to Central.
            3. Remove spool entry only after successful delivery.

        If Central submission fails, the spool entry is deliberately
        retained so it can be retried later.
        """

        path = self.spool.store(batch)

        try:
            self.client.submit_batch(batch)

        except Exception:
            # The spool entry is intentionally retained.
            raise

        else:
            # Only remove the spool entry after Central confirms
            # successful submission.
            self.spool.remove(path)

    def retry_spool(self) -> bool:
        """
        Retry all previously spooled evidence batches.

        Returns:
            True:
                No pending batches exist, or every pending batch
                was successfully delivered.

            False:
                At least one batch could not be delivered.

        Successfully delivered batches are removed from the spool.
        Failed batches remain in the spool.
        """

        pending = self.spool.pending()

        if not pending:
            return True

        all_delivered = True

        for path in pending:
            try:
                batch = self.spool.load(path)

                self.client.submit_batch(batch)

                # Remove only after successful submission.
                self.spool.remove(path)

            except Exception as exc:
                all_delivered = False

                print(
                    "[host-agent] spool retry failed: "
                    f"{path.name}: {exc}"
                )

        return all_delivered