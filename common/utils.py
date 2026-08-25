import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from enum import Enum


def generate_uuid() -> str:
    return str(uuid.uuid4())


def current_timestamp() -> datetime:
    return datetime.now(UTC)


def timestamp_string() -> str:
    return current_timestamp().isoformat()


def load_json(path: str | Path) -> dict[str, Any]:

    with open(path, encoding="utf-8") as file:
        return json.load(file)


def save_json(data: dict[str, Any], path: str | Path):

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def ensure_directory(path: str | Path):

    Path(path).mkdir(parents=True, exist_ok=True)

def canonical_tenant_identity(
    platform: str | Enum,
    platform_project_id: str,
) -> str:
    """
    Return the canonical platform-qualified tenant identity.

    Example:
        incus:government-a
    """

    platform_value = (
        platform.value
        if isinstance(platform, Enum)
        else platform
    )

    return (
        f"{platform_value.strip().lower()}:"
        f"{platform_project_id.strip()}"
    )


def deterministic_tenant_id(
    platform: str | Enum,
    platform_project_id: str,
) -> str:
    """
    Generate a deterministic internal tenant identifier.
    """

    canonical_identity = canonical_tenant_identity(
        platform,
        platform_project_id,
    )

    tenant_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL,
        canonical_identity,
    )

    return f"TENANT-{str(tenant_uuid).upper()}"