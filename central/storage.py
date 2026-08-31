from __future__ import annotations

import hashlib
from pathlib import Path


class RawEvidenceStore:

    def __init__(
        self,
        root: str = "/srv/evidence-objects",
    ):

        self.root = Path(root)

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def put(
        self,
        *,
        tenant_id: str,
        instance_name: str,
        evidence_type: str,
        raw_data: bytes,
        expected_sha256: str,
    ) -> tuple[str, str]:

        calculated = hashlib.sha256(
            raw_data
        ).hexdigest()

        if calculated != expected_sha256:
            raise ValueError(
                "Raw evidence SHA-256 mismatch"
            )

        object_key = (
            f"evidence/"
            f"{tenant_id}/"
            f"{instance_name}/"
            f"{evidence_type}/"
            f"{calculated}"
        )

        destination = (
            self.root
            / tenant_id
            / instance_name
            / evidence_type
            / calculated
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.exists():

            existing = destination.read_bytes()

            existing_hash = hashlib.sha256(
                existing
            ).hexdigest()

            if existing_hash != calculated:
                raise RuntimeError(
                    "Existing evidence object failed integrity check"
                )

            return object_key, calculated

        temporary = destination.with_suffix(
            ".tmp"
        )

        temporary.write_bytes(
            raw_data
        )

        temporary.replace(
            destination
        )

        return object_key, calculated

    def get(
        self,
        object_key: str,
    ) -> bytes:

        relative = object_key.removeprefix(
            "evidence/"
        )

        path = (
            self.root
            / relative
        )

        return path.read_bytes()