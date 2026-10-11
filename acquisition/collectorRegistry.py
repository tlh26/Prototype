from __future__ import annotations

from acquisition.collectors.base import EvidenceCollector


class CollectorRegistry:
    """
    Registry of evidence collectors indexed by source name.
    """

    def __init__(self) -> None:
        self._collectors: dict[
            str,
            EvidenceCollector,
        ] = {}

    def register(
        self,
        collector: EvidenceCollector,
    ) -> None:
        """
        Register a collector using its canonical source name.
        """

        source = collector.source

        if not source.strip():
            raise ValueError("collector source must not be empty")

        if source in self._collectors:
            raise ValueError(f"Collector already registered: {source}")

        self._collectors[source] = collector

    def get(
        self,
        source: str,
    ) -> EvidenceCollector:
        """
        Retrieve a collector by source name.
        """

        try:
            return self._collectors[source]
        except KeyError as exc:
            raise KeyError(f"No collector registered for source: {source}") from exc

    def has(
        self,
        source: str,
    ) -> bool:
        return source in self._collectors

    def sources(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors.keys()))
