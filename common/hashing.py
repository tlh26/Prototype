import hashlib
import hmac
import json
from typing import Any


class HashingService:

    @staticmethod
    def sha256(data: str | bytes) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")

        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def verify(
        data: bytes,
        expected_hash: str,
    ) -> bool:
        actual_hash = HashingService.sha256(data)
        return actual_hash == expected_hash

    @staticmethod
    def md5(data: str | bytes) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")

        return hashlib.md5(data).hexdigest()

    @staticmethod
    def hash_dictionary(data: dict[str, Any]) -> str:
        serialised = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return HashingService.sha256(serialised)

    @staticmethod
    def verify(data: str | bytes, expected_hash: str) -> bool:
        actual_hash = HashingService.sha256(data)

        return hmac.compare_digest(
            actual_hash,
            expected_hash,
        )
