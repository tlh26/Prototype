import logging
import os
import signal
import time

from evidenceAgent.agent import EvidenceAgent
from evidenceAgent.config import AgentConfig


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
    """
    Handle SIGINT (Ctrl+C) and SIGTERM gracefully.
    """
    global running

    signal_name = signal.Signals(signum).name

    logger.info(
        "Shutdown requested (%s)",
        signal_name,
    )

    running = False


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------

def main():
    global running

    # Register graceful shutdown handlers.
    signal.signal(signal.SIGINT, stop_agent)
    signal.signal(signal.SIGTERM, stop_agent)

    # Load configuration from environment variables.
    config = AgentConfig.from_environment()

    logger.info("==================================================")
    logger.info("Evidence Agent Starting")
    logger.info("==================================================")
    logger.info("Tenant    : %s", config.tenant_id)
    logger.info("Instance  : %s", config.instance_name)
    logger.info("Agent ID  : %s", config.agent_id)

    interval = getattr(
        config,
        "collection_interval",
        10,
    )

    logger.info("Interval  : %s seconds", interval)
    logger.info("==================================================")

    # Create the evidence agent.
    agent = EvidenceAgent(config)

    logger.info("Agent ready; beginning evidence collection")

    cycle = 0

    while running:
        cycle += 1

        logger.info(
            "Collection cycle %d started",
            cycle,
        )

        try:
            agent.collect_once()

            logger.info(
                "Collection cycle %d completed successfully",
                cycle,
            )

        except Exception:
            logger.exception(
                "Collection cycle %d failed",
                cycle,
            )

        # Only sleep if the agent has not been asked to stop.
        if running:
            logger.info(
                "Waiting %s seconds until next collection cycle",
                interval,
            )

            time.sleep(interval)

    logger.info("==================================================")
    logger.info("Evidence Agent Stopped")
    logger.info("==================================================")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()