from __future__ import annotations

import json

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

        payload["raw_data"] = (
            event.raw_data.decode(
                "utf-8",
                errors="replace",
            )
        )

        response = requests.post(
            f"{self.base_url}/api/v1/evidence",
            json=payload,
            headers={
                "Authorization":
                    f"Bearer {self.api_key}",
            },
            timeout=10,
        )

        response.raise_for_status()