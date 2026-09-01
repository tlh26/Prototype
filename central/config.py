from dataclasses import dataclass
import os


@dataclass(frozen=True)
class CentralConfig:
    host: str = os.getenv("CENTRAL_HOST", "0.0.0.0")
    port: int = int(os.getenv("CENTRAL_PORT", "9443"))
    database_path: str = os.getenv(
        "CENTRAL_DATABASE",
        "storage/evidence.db",
    )
    api_key: str = os.getenv(
        "EVIDENCE_API_KEY",
        "change-me",
    )