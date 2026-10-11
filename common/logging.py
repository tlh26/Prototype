import logging
from pathlib import Path

from common.config import settings

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "prototype.log"


def configure_logging() -> logging.Logger:

    logger = logging.getLogger(settings.APP_NAME)

    if logger.handlers:
        return logger

    logger.setLevel(settings.LOG_LEVEL)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)

    logger.addHandler(console)
    logger.addHandler(file_handler)

    return logger


# ========================================
""" USAGE
# from common.logging import configure_logging

# logger = configure_logging()

# logger.info("Prototype started")  """
