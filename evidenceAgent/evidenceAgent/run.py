from __future__ import annotations

import logging
import os
import signal
import threading
import time

from .agent import EvidenceAgent
from .config import AgentConfig
from .hostAgent import HostEvidenceAgent
from .hostConfig import HostAgentConfig

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("EVIDENCE_LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("evidence-agent")


# ---------------------------------------------------------------------------
# Agent lifecycle state
# ---------------------------------------------------------------------------

running = True


def stop_agent(signum, frame):
    """Handle SIGINT and SIGTERM gracefully."""
    global running

    signal_name = signal.Signals(signum).name
    logger.info("Shutdown requested (%s)", signal_name)
    running = False


# ---------------------------------------------------------------------------
# Host-agent enablement
# ---------------------------------------------------------------------------


def host_enabled() -> bool:
    """
    Determine whether the host-level audit agent should run.

    The host agent is disabled by default because the standalone
    evidenceAgent package is also deployed inside Incus instances,
    where the host-only acquisition package is not installed.
    """
    return os.getenv(
        "EVIDENCE_HOST_AGENT_ENABLED",
        "false",
    ).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def instance_loop(
    agent: EvidenceAgent,
    interval: int,
) -> None:
    """Run the instance-level evidence agent."""
    cycle = 0

    while running:
        cycle += 1

        logger.info(
            "[instance] Collection cycle %d started",
            cycle,
        )

        try:
            agent.collect_once()

            logger.info(
                "[instance] Collection cycle %d completed",
                cycle,
            )

        except Exception:
            logger.exception(
                "[instance] Collection cycle %d failed",
                cycle,
            )

        if running:
            time.sleep(interval)


def instance_enabled() -> bool:
    """
    Determine whether the instance-level evidence agent should run.

    Enabled by default so existing instance deployments continue to work.
    Set EVIDENCE_INSTANCE_AGENT_ENABLED=false on an Incus host running
    the host agent only.
    """
    return os.getenv(
        "EVIDENCE_INSTANCE_AGENT_ENABLED",
        "true",
    ).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def host_loop(
    agent: HostEvidenceAgent,
    interval: int,
) -> None:
    """
    Run host-level audit evidence acquisition.

    New audit evidence is collected only when there are no pending
    spool entries. The checkpoint is committed only after successful
    delivery.
    """
    cycle = 0

    while running:
        cycle += 1

        logger.info(
            "[host] Collection cycle %d started",
            cycle,
        )

        try:
            # ---------------------------------------------------------------
            # 1. Retry previously spooled batches first.
            # ---------------------------------------------------------------

            spool_clear = agent.retry_spool()

            if not spool_clear:
                logger.warning(
                    "[host] Pending spool entries remain; "
                    "skipping new audit collection this cycle"
                )

            else:
                result = agent.collect()
                evidence_count = len(result.batch.evidence)

                if evidence_count == 0:
                    logger.info("[host] No new audit evidence")

                else:
                    logger.info(
                        "[host] Collected %d audit evidence events",
                        evidence_count,
                    )

                    # -------------------------------------------------------
                    # 3. Deliver batch.
                    #
                    #    process_batch() removes the spool entry only after
                    #    successful Central submission.
                    # -------------------------------------------------------

                    agent.process_batch(result.batch)

                    # -------------------------------------------------------
                    # 4. Commit checkpoint only after successful delivery.
                    # -------------------------------------------------------

                    agent.collector.commit_checkpoint(result.checkpoint)

                    logger.info(
                        "[host] Delivered batch and committed " "audit checkpoint"
                    )

        except Exception:
            logger.exception(
                "[host] Collection cycle %d failed",
                cycle,
            )

        if running:
            time.sleep(interval)


def build_host_agent(
    config: HostAgentConfig,
) -> HostEvidenceAgent:
    """
    Construct the host-level evidence agent.

    The acquisition package is imported lazily here because it is a
    host-only dependency. Instance deployments do not need acquisition/*
    installed in their standalone evidenceAgent environment.
    """

    from acquisition.checkpoint import CheckpointStore
    from acquisition.collectors.audit import AuditCollector
    from acquisition.collectors.auditAttributor import (
        IncusAuditAttributor,
    )
    from acquisition.collectors.hostExec import HostExecutor

    checkpoint_store = CheckpointStore(config.checkpoint_path)

    collector = AuditCollector(
        executor=HostExecutor(use_sudo=True),
        checkpoint_store=checkpoint_store,
        attributor=IncusAuditAttributor(),
        host_id="incus-host",
    )

    return HostEvidenceAgent(
        config=config,
        collector=collector,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global running

    # -----------------------------------------------------------------------
    # Signal handlers
    # -----------------------------------------------------------------------

    signal.signal(
        signal.SIGINT,
        stop_agent,
    )

    signal.signal(
        signal.SIGTERM,
        stop_agent,
    )

    # -----------------------------------------------------------------------
    # Determine deployment mode
    # -----------------------------------------------------------------------

    instance_is_enabled = instance_enabled()
    host_is_enabled = host_enabled()

    if not instance_is_enabled and not host_is_enabled:
        raise RuntimeError(
            "No evidence agent is enabled. "
            "Set EVIDENCE_INSTANCE_AGENT_ENABLED=true "
            "and/or EVIDENCE_HOST_AGENT_ENABLED=true."
        )

    # -----------------------------------------------------------------------
    # Load instance configuration only when instance agent is enabled.
    # -----------------------------------------------------------------------

    instance_config = None

    if instance_is_enabled:
        instance_config = AgentConfig.from_environment()

    # -----------------------------------------------------------------------
    # Load host configuration only when host agent is enabled.
    # -----------------------------------------------------------------------

    host_config = None
    host_agent = None

    if host_is_enabled:
        host_config = HostAgentConfig.from_environment()
        host_agent = build_host_agent(host_config)

    # -----------------------------------------------------------------------
    # Startup information
    # -----------------------------------------------------------------------

    logger.info("==================================================")
    logger.info("Evidence Agent Starting")
    logger.info("==================================================")

    logger.info(
        "Instance agent : %s",
        "enabled" if instance_is_enabled else "disabled",
    )

    if instance_config is not None:
        logger.info(
            "Instance tenant : %s",
            instance_config.tenant_id,
        )

        logger.info(
            "Instance name   : %s",
            instance_config.instance_name,
        )

        logger.info(
            "Instance agent ID: %s",
            instance_config.agent_id,
        )

        logger.info(
            "Central URL     : %s",
            instance_config.central_url,
        )

        logger.info(
            "Instance interval: %s seconds",
            getattr(
                instance_config,
                "collection_interval",
                10,
            ),
        )

    logger.info(
        "Host agent      : %s",
        "enabled" if host_is_enabled else "disabled",
    )

    if host_config is not None:
        logger.info(
            "Host audit path : %s",
            host_config.audit_path,
        )

        logger.info(
            "Host checkpoint : %s",
            host_config.checkpoint_path,
        )

        logger.info(
            "Host spool      : %s",
            host_config.spool_directory,
        )

        logger.info(
            "Host interval   : %s seconds",
            host_config.interval,
        )

    logger.info("==================================================")

    # -----------------------------------------------------------------------
    # Construct instance-level agent
    # -----------------------------------------------------------------------

    instance_agent = None

    if instance_config is not None:
        instance_agent = EvidenceAgent(instance_config)
        logger.info("Instance agent ready")

    # -----------------------------------------------------------------------
    # Start instance loop
    # -----------------------------------------------------------------------

    instance_thread = None

    if instance_agent is not None:
        instance_thread = threading.Thread(
            target=instance_loop,
            args=(
                instance_agent,
                getattr(
                    instance_config,
                    "collection_interval",
                    10,
                ),
            ),
            name="instance-agent",
        )

        instance_thread.start()

    # -----------------------------------------------------------------------
    # Start host loop
    # -----------------------------------------------------------------------

    host_thread = None

    if host_agent is not None:
        logger.info("Host agent ready")

        host_thread = threading.Thread(
            target=host_loop,
            args=(
                host_agent,
                host_config.interval,
            ),
            name="host-agent",
        )

        host_thread.start()

    # -----------------------------------------------------------------------
    # Report active configuration
    # -----------------------------------------------------------------------

    if instance_agent is not None and host_agent is not None:
        logger.info("Evidence collection started: " "instance + host audit")

    elif instance_agent is not None:
        logger.info("Evidence collection started: " "instance agent only")

    else:
        logger.info("Evidence collection started: " "host audit agent only")

    # -----------------------------------------------------------------------
    # Wait for workers to finish
    # -----------------------------------------------------------------------

    if instance_thread is not None:
        instance_thread.join()

    if host_thread is not None:
        host_thread.join()

    logger.info("==================================================")
    logger.info("Evidence Agent Stopped")
    logger.info("==================================================")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
