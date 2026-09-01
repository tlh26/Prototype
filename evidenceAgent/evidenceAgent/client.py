from __future__ import annotations

import base64

import requests


class CentralEvidenceClient:

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def submit(
        self,
        event,
    ) -> None:

        payload = event.model_dump()

        payload["timestamp"] = (
            event.timestamp.isoformat()
        )

        payload["created_at"] = (
            event.created_at.isoformat()
        )

        # Preserve the original evidence bytes.
        # Central expects raw_data to be Base64 encoded.
        payload["raw_data"] = base64.b64encode(
            event.raw_data
        ).decode("ascii")

        response = requests.post(
            f"{self.base_url}/api/v1/evidence/events",
            json=payload,
            headers={
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=10,
        )

        response.raise_for_status()