from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field


class CaptureStatus(str, Enum):
    """
    Overall status of an evidence capture operation.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class SourceCaptureStatus(str, Enum):
    """
    Status of an individual evidence source.
    """

    SUCCESS = "success"
    FAILED = "failed"


class CaptureSourceResult(BaseModel):
    """
    Result of attempting to acquire one evidence source.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    source: str

    status: SourceCaptureStatus

    evidence_id: str | None = None

    sha256: str | None = None

    size_bytes: int | None = None

    error: str | None = None


class CaptureManifest(BaseModel):
    """
    Immutable record describing one evidence acquisition
    operation.

    The manifest records what was requested, what succeeded,
    and what failed.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    capture_id: str

    tenant_id: str

    tenant_hash: str

    project_id: str

    instance_name: str

    started_at: datetime

    completed_at: datetime | None = None

    status: CaptureStatus = CaptureStatus.FAILED

    sources: tuple[CaptureSourceResult, ...] = Field(default_factory=tuple)

    @property
    def successful_sources(self) -> tuple[CaptureSourceResult, ...]:
        return tuple(
            source
            for source in self.sources
            if source.status == SourceCaptureStatus.SUCCESS
        )

    @property
    def failed_sources(self) -> tuple[CaptureSourceResult, ...]:
        return tuple(
            source
            for source in self.sources
            if source.status == SourceCaptureStatus.FAILED
        )

    @property
    def evidence_count(self) -> int:
        return len(self.successful_sources)

    @classmethod
    def create(
        cls,
        *,
        capture_id: str,
        tenant_id: str,
        tenant_hash: str,
        project_id: str,
        instance_name: str,
        started_at: datetime | None = None,
    ) -> "CaptureManifest":

        return cls(
            capture_id=capture_id,
            tenant_id=tenant_id,
            tenant_hash=tenant_hash,
            project_id=project_id,
            instance_name=instance_name,
            started_at=(
                started_at if started_at is not None else datetime.now(timezone.utc)
            ),
        )

    def complete(
        self,
        results: Iterable[CaptureSourceResult],
    ) -> "CaptureManifest":

        source_results = tuple(results)

        successful = [
            result
            for result in source_results
            if result.status == SourceCaptureStatus.SUCCESS
        ]

        failed = [
            result
            for result in source_results
            if result.status == SourceCaptureStatus.FAILED
        ]

        if not failed:
            status = CaptureStatus.SUCCESS
        elif successful:
            status = CaptureStatus.PARTIAL
        else:
            status = CaptureStatus.FAILED

        return self.model_copy(
            update={
                "completed_at": datetime.now(timezone.utc),
                "status": status,
                "sources": source_results,
            }
        )
