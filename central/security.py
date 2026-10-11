from fastapi import Header, HTTPException

from central.config import CentralConfig


def verify_api_key(
    x_api_key: str | None,
    config: CentralConfig,
) -> None:

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key",
        )

    if x_api_key != config.api_key:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key",
        )
