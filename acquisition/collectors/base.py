from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

T = TypeVar("T")


class CollectorError(RuntimeError):
    """
    Raised when an evidence collector cannot successfully
    acquire evidence from its configured source.

    This exception represents an acquisition-layer failure.
    Source-specific exceptions should normally be wrapped in
    CollectorError before propagating to higher layers.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
    ) -> None:
        self.source = source

        if source:
            message = f"[{source}] {message}"

        super().__init__(message)


class EvidenceCollector(ABC, Generic[T]):
    """
    Abstract base class for evidence collectors.

    A collector is responsible for acquiring evidence from a
    particular source and returning an evidence representation.

    Collectors belong to the acquisition layer and therefore
    should focus on:

        1. Identifying the configured evidence source.
        2. Acquiring the source data.
        3. Preserving the acquired data.
        4. Providing acquisition metadata required by the
           evidence model.

    Collectors should NOT perform higher-level forensic
    interpretation, correlation, or investigation logic.

    Examples of concrete collectors include:

        AuditCollector
        JournalCollector
        NginxCollector
        ApiCollector
        PostgresCollector

    Generic type parameter:
        T:
            The type of evidence object returned by the
            concrete collector.
    """

    @property
    @abstractmethod
    def source(self) -> str:
        """
        Return the canonical identifier of the evidence source.

        Examples:

            "auditd"
            "journald"
            "nginx"
            "api"
            "postgresql"

        Returns:
            A stable source identifier.
        """
        raise NotImplementedError

    @abstractmethod
    def collect(self, *args, **kwargs) -> T:
        """
        Acquire evidence from the configured source.

        Concrete collectors must implement this method.

        The implementation should:

            - acquire the source evidence;
            - preserve the acquired evidence;
            - attach appropriate provenance;
            - calculate integrity information where required;
            - return the collector-specific evidence object.

        It should not perform higher-level event correlation.

        Returns:
            The acquired evidence object.

        Raises:
            CollectorError:
                If evidence cannot be successfully acquired.
        """
        raise NotImplementedError
