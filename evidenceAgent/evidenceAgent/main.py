from evidenceAgent.agent import EvidenceAgent
from evidenceAgent.config import AgentConfig


def main():

    config = AgentConfig.from_environment()

    agent = EvidenceAgent(
        config
    )

    agent.run()


if __name__ == "__main__":
    main()