"""
Application configuration.
"""

from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")


class Settings(BaseSettings):
    """Global application settings."""

    APP_NAME: str = "Cloud Evidence Correlation Prototype"

    VERSION: str = "0.1.0"

    DEBUG: bool = True

    LOG_LEVEL: str = "INFO"

    HASH_ALGORITHM: str = "sha256"

    ELASTICSEARCH_HOST: str = "http://localhost:9200"

    ELASTICSEARCH_INDEX: str = "evidence"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# from pydantic import BaseModel


# class Settings(BaseModel):

#     APP_NAME: str = "Evidence Correlation Prototype"

#     VERSION: str = "0.1"

#     DEBUG: bool = True


# settings = Settings()
