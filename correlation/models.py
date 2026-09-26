from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceLayer(str, Enum):
    """Layer from which evidence originated."""

    INSTANCE = "instance"
    HOST = "host"


class CanonicalEvidence(BaseModel):
    """
    Normalized evidence representation used by the correlation layer.

    This is derived data. It does not replace the authoritative records
    stored in evidence_events or evidence_records.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # ------------------------------------------------------------------
    # Stable identifier from the original evidence source
    # ------------------------------------------------------------------
    evidence_id: str

    # ------------------------------------------------------------------
    # Tenant and platform context
    # ------------------------------------------------------------------
    tenant_id: str | None = None
    project_id: str | None = None
    instance_name: str | None = None

    # ------------------------------------------------------------------
    # Evidence origin
    # ------------------------------------------------------------------
    layer: EvidenceLayer

    # ------------------------------------------------------------------
    # Normalized classification
    # ------------------------------------------------------------------
    evidence_type: str
    event_type: str
    source: str
    source_path: str | None = None

    # ------------------------------------------------------------------
    # Temporal information
    # ------------------------------------------------------------------
    # May be unavailable for host records until the audit timestamp
    # is parsed from raw_data.
    event_timestamp: datetime | None = None

    # Time at which evidence was collected/persisted.
    collected_at: datetime

    # ------------------------------------------------------------------
    # Common correlation fields
    # ------------------------------------------------------------------
    actor: str | None = None
    uid: int | None = None
    resource: str | None = None

    # ------------------------------------------------------------------
    # Normalized source-specific fields
    # ------------------------------------------------------------------
    attributes: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Original evidence and integrity information
    # ------------------------------------------------------------------
    raw_data: bytes
    sha256: str

    # ------------------------------------------------------------------
    # Agent and sequence metadata
    # ------------------------------------------------------------------
    agent_id: str | None = None
    sequence_start: int | None = None
    sequence_end: int | None = None

    # ------------------------------------------------------------------
    # Acquisition and provenance metadata
    # ------------------------------------------------------------------
    provenance: dict[str, Any] = Field(default_factory=dict)


class EvidenceReference(BaseModel):
    """
    Lightweight reference from derived correlation data to original evidence.

    Correlation results should reference original evidence rather than
    duplicate its raw data.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str
    source_table: str
    sha256: str


class EntityType(str, Enum):
    """Entity types recognized by the correlation layer."""

    TENANT = "tenant"
    PROJECT = "project"
    INSTANCE = "instance"
    USER = "user"
    RESOURCE = "resource"
    PROCESS = "process"


class EvidenceEntity(BaseModel):
    """
    Entity extracted from one or more canonical evidence items.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    entity_id: str
    entity_type: EntityType
    value: str

    # Tenant context is deliberately retained so that identical values
    # in different tenants do not collapse into the same analytical entity.
    tenant_id: str | None = None
    instance_name: str | None = None

    # Traceability back to the originating evidence.
    evidence_ids: tuple[str, ...] = ()


class RelationshipType(str, Enum):
    """Relationship types between extracted entities."""

    BELONGS_TO = "belongs_to"
    OCCURRED_ON = "occurred_on"
    ACTED_ON = "acted_on"
    REFERENCES = "references"

    # Analytical relationship produced by a correlation rule.
    CORRELATES_WITH = "correlates_with"


class EvidenceRelationship(BaseModel):
    """
    Relationship between two extracted entities.

    Relationships are derived data and retain references to the
    evidence supporting the relationship.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    relationship_id: str
    source_entity_id: str
    relationship_type: RelationshipType
    target_entity_id: str
    evidence_ids: tuple[str, ...] = ()


class FindingSeverity(str, Enum):
    """Severity assigned by a correlation rule."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
