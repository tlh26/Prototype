from dataclasses import dataclass
import os


@dataclass(frozen=True)
class CentralConfig:
    host: str = os.getenv(
        "CENTRAL_HOST",
        "0.0.0.0",
    )

    port: int = int(
        os.getenv(
            "CENTRAL_PORT",
            "9443",
        )
    )

    database_url: str = os.getenv(
        "CENTRAL_DATABASE_URL",
        "",
    )

    api_key: str = os.getenv(
        "EVIDENCE_API_KEY",
        "change-me",
    )

    def __post_init__(self) -> None:
        if not self.database_url:
            raise RuntimeError("CENTRAL_DATABASE_URL is not configured.")
