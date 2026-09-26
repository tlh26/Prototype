from __future__ import annotations

import base64

import requests

from .transportModels import EvidenceBatch


class CentralEvidenceClient:

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # ========================================================================
    # Per-event delivery
    # ========================================================================

    def submit(
        self,
        event,
    ) -> None:
        """
        Submit one EvidenceEvent to Central.

        Used by the per-instance EvidenceAgent.
        """

        payload = event.model_dump()

        payload["timestamp"] = event.timestamp.isoformat()

        payload["created_at"] = event.created_at.isoformat()

        # Preserve the original evidence bytes.
        # Central expects raw_data to be Base64 encoded.
        payload["raw_data"] = base64.b64encode(event.raw_data).decode("ascii")

        response = requests.post(
            (f"{self.base_url}" "/api/v1/evidence/events"),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )

        if not response.ok:
            raise RuntimeError(
                f"Central rejected evidence event: "
                f"HTTP {response.status_code}: {response.text}"
            )

        response.raise_for_status()

    # ========================================================================
    # Batch delivery
    # ========================================================================

    def submit_batch(
        self,
        batch: EvidenceBatch,
    ) -> None:
        """
        Submit one EvidenceBatch to Central.

        Used by the host EvidenceAgent.

        EvidenceEnvelope.raw_data_b64 already contains the Base64
        representation of the original evidence bytes, so it must
        NOT be Base64 encoded again here.
        """

        payload = batch.model_dump(mode="json")

        response = requests.post(
            (f"{self.base_url}" "/api/v1/evidence/batches"),
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )

        if not response.ok:
            raise RuntimeError(
                f"Central rejected evidence batch: "
                f"HTTP {response.status_code}: {response.text}"
            )

        response.raise_for_status()

        # ack = self.client.submit_batch(batch)

        # print(
        #     "[host-agent] Central acknowledgement: "
        #     f"{ack}"
        # )

    # ========================================================================
    # HTTP helpers
    # ========================================================================

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }
