# acquisition/collectors/base.py

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar


T = TypeVar("T")


class CollectorError(RuntimeError):
    """Raised when evidence acquisition fails."""


class EvidenceCollector(ABC, Generic[T]):
    """
    Base interface for evidence collectors.

    Collectors acquire source evidence.
    They should not perform higher-level forensic interpretation.
    """

    @abstractmethod
    def collect(self, *args, **kwargs) -> T:
        """
        Acquire evidence from the configured source.
        """
        raise NotImplementedError