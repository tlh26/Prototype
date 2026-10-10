# correlation/models.py
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Evidence models
# ============================================================================

class EvidenceLayer(str, Enum):
    """Layer from which evidence originated."""

    INSTANCE = "instance"
    HOST = "host"


class CanonicalEvidence(BaseModel):
    """
    Normalized evidence representation used by the correlation layer.

    This is derived data. It does not replace the authoritative records
    stored in the central evidence repository.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str
    tenant_id: str | None = None
    project_id: str | None = None
    instance_name: str | None = None
    layer: EvidenceLayer
    evidence_type: str
    event_type: str
    source: str
    source_path: str | None = None
    event_timestamp: datetime | None = None
    collected_at: datetime
    actor: str | None = None
    uid: int | None = None
    resource: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_data: bytes
    sha256: str
    agent_id: str | None = None
    sequence_start: int | None = None
    sequence_end: int | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class EvidenceReference(BaseModel):
    """Lightweight reference to authoritative source evidence."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str
    source_table: str
    sha256: str


# ============================================================================
# Entity and relationship models
# ============================================================================

class EntityType(str, Enum):
    """Entity types recognized by the correlation layer."""

    TENANT = "tenant"
    PROJECT = "project"
    INSTANCE = "instance"
    USER = "user"
    RESOURCE = "resource"
    PROCESS = "process"


class EvidenceEntity(BaseModel):
    """Entity extracted from one or more canonical evidence items."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    entity_id: str
    entity_type: EntityType
    value: str
    tenant_id: str | None = None
    instance_name: str | None = None
    evidence_ids: tuple[str, ...] = ()


class RelationshipType(str, Enum):
    """Relationship types between extracted entities."""

    BELONGS_TO = "belongs_to"
    OCCURRED_ON = "occurred_on"
    ACTED_ON = "acted_on"
    REFERENCES = "references"
    CORRELATES_WITH = "correlates_with"


class EvidenceRelationship(BaseModel):
    """Relationship between two extracted entities."""

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
    """Severity assigned to a correlation finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ============================================================================
# Correlation configuration
# ============================================================================

class PrivacyMode(str, Enum):
    """Representation mode used when extracting and comparing features."""

    RAW = "raw"
    PSEUDONYMISED = "pseudonymised"
    GENERALISED = "generalised"
    RESTRICTED = "restricted"


class CorrelationContext(BaseModel):
    """Immutable configuration and execution context for one analysis."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    analysis_id: str = Field(
        ...,
        min_length=1,
        description="Stable identifier for this correlation analysis.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time at which the analysis context was created.",
    )

    requested_tenants: tuple[str, ...] = Field(
        default=(),
        description=(
            "Tenants explicitly included in this analysis. "
            "An empty tuple delegates tenant selection to the caller/source."
        ),
    )

    allow_cross_tenant: bool = Field(
        default=False,
        description=(
            "Whether candidates spanning multiple tenants may be evaluated."
        ),
    )

    allowed_tenant_pairs: tuple[tuple[str, str], ...] = Field(
        default=(),
        description=(
            "Explicitly authorised tenant pairs. Pairs are treated "
            "as unordered."
        ),
    )

    start_time: datetime | None = None
    end_time: datetime | None = None

    temporal_window_seconds: float = Field(
        default=60.0,
        gt=0,
        description=(
            "Maximum timestamp difference initially considered "
            "for temporal candidate generation."
        ),
    )

    privacy_mode: PrivacyMode = PrivacyMode.RAW

    permitted_feature_types: tuple[str, ...] = Field(
        default=(
            "temporal",
            "entity",
            "resource",
            "action",
            "provenance",
        ),
        description="Feature families permitted during this analysis.",
    )

    minimum_score: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Minimum weighted score required for a finding.",
    )

    minimum_feature_count: int = Field(
        default=1,
        ge=1,
        description="Minimum number of valid features required for scoring.",
    )

    configuration_version: str = Field(
        default="1.0",
        min_length=1,
        description="Version of the correlation configuration.",
    )

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("end_time")
    @classmethod
    def validate_time_range(
        cls,
        value: datetime | None,
        info: Any,
    ) -> datetime | None:
        start_time = info.data.get("start_time")

        if (
            value is not None
            and start_time is not None
            and value < start_time
        ):
            raise ValueError(
                "end_time must be greater than or equal to start_time"
            )

        return value

    @field_validator("allowed_tenant_pairs")
    @classmethod
    def validate_tenant_pairs(
        cls,
        value: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        for pair in value:
            if len(pair) != 2:
                raise ValueError(
                    "Each allowed tenant pair must contain exactly two tenant IDs"
                )

            tenant_a, tenant_b = pair

            if not tenant_a or not tenant_b:
                raise ValueError(
                    "Tenant IDs in allowed_tenant_pairs cannot be empty"
                )

            if tenant_a == tenant_b:
                raise ValueError(
                    "allowed_tenant_pairs must contain distinct tenant IDs"
                )

        return value


# ============================================================================
# Candidate models
# ============================================================================

class CandidateType(str, Enum):
    """Classification of the relationship being evaluated."""

    PAIR = "pair"
    GROUP = "group"
    INCIDENT = "incident"


class CorrelationCandidate(BaseModel):
    """
    Evidence candidate considered by the correlation engine.

    A candidate is not yet a finding.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    candidate_id: str = Field(
        ...,
        min_length=1,
        description="Deterministic or otherwise stable candidate identifier.",
    )

    candidate_type: CandidateType = CandidateType.PAIR

    evidence_ids: tuple[str, ...] = Field(
        ...,
        min_length=2,
        description="Evidence records participating in this candidate.",
    )

    evidence_references: tuple[EvidenceReference, ...] = ()
    tenant_ids: tuple[str, ...] = ()
    cross_tenant: bool = False

    generation_reasons: tuple[str, ...] = Field(
        default=(),
        description="Reasons explaining why this candidate was generated.",
    )

    blocking_keys: tuple[str, ...] = Field(
        default=(),
        description="Keys used by candidate generation/blocking.",
    )

    earliest_timestamp: datetime | None = None
    latest_timestamp: datetime | None = None

    time_delta_seconds: float | None = Field(
        default=None,
        ge=0,
    )

    shared_entity_ids: tuple[str, ...] = ()
    shared_resources: tuple[str, ...] = ()
    related_actions: tuple[str, ...] = ()
    provenance: tuple[ProvenanceReference, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("evidence_ids must be unique")

        if len(value) < 2:
            raise ValueError(
                "A correlation candidate requires at least two evidence IDs"
            )

        return value

    @field_validator("tenant_ids")
    @classmethod
    def validate_tenant_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("tenant_ids must be unique")

        return value


# ============================================================================
# Causal reasoning models
# ============================================================================

class CausalRelation(str, Enum):
    """
    Explainable causal relationships between evidence events.

    REQUIRES:
        The source event depends on the target event or state.

    PROVIDES:
        The source event establishes or creates something subsequently
        used by the target event.

    ENABLES:
        The source event establishes a condition under which the target
        event can occur.
    """

    REQUIRES = "requires"
    PROVIDES = "provides"
    ENABLES = "enables"


class CausalLink(BaseModel):
    """Explainable causal relationship inferred from two evidence records."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    relationship_id: str = Field(..., min_length=1)
    relation: CausalRelation

    source_evidence_id: str = Field(..., min_length=1)
    target_evidence_id: str = Field(..., min_length=1)

    source_action: str = Field(..., min_length=1)
    target_action: str = Field(..., min_length=1)

    evidence_ids: tuple[str, ...] = ()
    tenant_ids: tuple[str, ...] = ()
    cross_tenant: bool = False

    temporal_delta_seconds: float = Field(..., ge=0.0)
    confidence: float = Field(..., ge=0.0, le=1.0)

    explanation: str = Field(..., min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) < 2:
            raise ValueError("A causal link requires at least two evidence IDs")

        if len(set(value)) != len(value):
            raise ValueError("Causal link evidence_ids must be unique")

        return value

    @field_validator("tenant_ids")
    @classmethod
    def validate_tenant_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Causal link tenant_ids must be unique")

        return value

    @field_validator("cross_tenant")
    @classmethod
    def validate_cross_tenant(
        cls,
        value: bool,
        info: Any,
    ) -> bool:
        tenant_ids = info.data.get("tenant_ids")

        if tenant_ids:
            expected = len(set(tenant_ids)) > 1

            if value != expected:
                raise ValueError(
                    "cross_tenant must agree with tenant_ids"
                )

        return value


class CausalReasoningResult(BaseModel):
    """
    Complete causal reasoning result for one candidate.

    Zero relationships is a valid result: the candidate was evaluated,
    but no supported causal rule matched.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    candidate_id: str = Field(..., min_length=1)
    relationships: tuple[CausalLink, ...] = ()
    considered: bool = True

    relationship_count: int = Field(
        default=0,
        ge=0,
    )

    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("relationship_count")
    @classmethod
    def validate_relationship_count(
        cls,
        value: int,
        info: Any,
    ) -> int:
        relationships = info.data.get("relationships")

        if (
            relationships is not None
            and value != len(relationships)
        ):
            raise ValueError(
                "relationship_count must equal the number of relationships"
            )

        return value


# ============================================================================
# Scoring models
# ============================================================================

class CorrelationFeature(BaseModel):
    """One explainable feature contributing to a correlation score."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    feature_name: str = Field(..., min_length=1)

    value: float = Field(..., ge=0.0, le=1.0)
    weight: float = Field(..., ge=0.0, le=1.0)
    contribution: float = Field(..., ge=0.0, le=1.0)

    explanation: str = Field(..., min_length=1)
    evidence_ids: tuple[str, ...] = ()
    attributes_used: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("contribution")
    @classmethod
    def validate_contribution(
        cls,
        value: float,
        info: Any,
    ) -> float:
        feature_value = info.data.get("value")
        weight = info.data.get("weight")

        if feature_value is not None and weight is not None:
            expected = feature_value * weight

            if abs(value - expected) > 1e-9:
                raise ValueError(
                    "contribution must equal value × weight "
                    f"(expected {expected}, received {value})"
                )

        return value


class CorrelationScore(BaseModel):
    """Complete explainable score for a correlation candidate."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    value: float = Field(..., ge=0.0, le=1.0)
    threshold: float = Field(..., ge=0.0, le=1.0)
    passed: bool

    features: tuple[CorrelationFeature, ...] = ()

    scoring_method: str = Field(
        default="weighted_sum",
        min_length=1,
    )

    weight_sum: float = Field(default=1.0, ge=0.0)
    valid_feature_count: int = Field(default=0, ge=0)
    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("passed")
    @classmethod
    def validate_passed(
        cls,
        value: bool,
        info: Any,
    ) -> bool:
        score = info.data.get("value")
        threshold = info.data.get("threshold")

        if score is not None and threshold is not None:
            expected = score >= threshold

            if value != expected:
                raise ValueError(
                    "passed must equal (value >= threshold)"
                )

        return value

    @field_validator("weight_sum")
    @classmethod
    def validate_weight_sum(
        cls,
        value: float,
        info: Any,
    ) -> float:
        features = info.data.get("features")

        if features:
            calculated = sum(feature.weight for feature in features)

            if abs(calculated - value) > 1e-9:
                raise ValueError(
                    "weight_sum must equal the sum of feature weights"
                )

        return value


# ============================================================================
# Provenance
# ============================================================================

class ProvenanceReference(BaseModel):
    """
    Immutable provenance reference from a derived correlation object
    back to authoritative source evidence.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str = Field(..., min_length=1)

    source_table: str = Field(
        ...,
        min_length=1,
        description="Authoritative table/repository containing the evidence.",
    )

    sha256: str = Field(..., min_length=1)

    tenant_id: str | None = None
    project_id: str | None = None
    instance_name: str | None = None
    evidence_layer: EvidenceLayer | None = None
    evidence_type: str | None = None
    source: str | None = None

    derived_from: str | None = None

    relationship: str = Field(
        default="supports",
        min_length=1,
    )

    captured_at: datetime | None = None
    sequence_start: int | None = None
    sequence_end: int | None = None
    integrity_verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(
        cls,
        value: str,
    ) -> str:
        normalized = value.lower()

        if len(normalized) != 64:
            raise ValueError(
                "sha256 must contain exactly 64 hexadecimal characters"
            )

        if any(
            character not in "0123456789abcdef"
            for character in normalized
        ):
            raise ValueError(
                "sha256 must contain only hexadecimal characters"
            )

        return normalized


# ============================================================================
# Finding models
# ============================================================================

class FindingStatus(str, Enum):
    """Lifecycle/status of a correlation finding."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REVIEW = "review"


class CorrelationFinding(BaseModel):
    """
    Explainable, provenance-preserving correlation finding.

    Causal relationships supplement the correlation score and do not
    replace the underlying authoritative evidence.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    finding_id: str = Field(..., min_length=1)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    status: FindingStatus = FindingStatus.CONFIRMED
    severity: FindingSeverity = FindingSeverity.INFO

    candidate_id: str
    analysis_id: str

    tenant_ids: tuple[str, ...] = ()
    cross_tenant: bool = False

    evidence_ids: tuple[str, ...] = ()
    evidence_references: tuple[EvidenceReference, ...] = ()
    provenance: tuple[ProvenanceReference, ...] = ()

    score: CorrelationScore

    explanation: str = Field(..., min_length=1)
    reason_codes: tuple[str, ...] = ()
    entity_ids: tuple[str, ...] = ()
    relationship_ids: tuple[str, ...] = ()

    # Phase 3: causal reasoning.
    causal_relationship_ids: tuple[str, ...] = ()
    causal_relationships: tuple[CausalLink, ...] = ()

    graph_edge_id: str | None = None

    policy_id: str | None = None
    policy_allowed: bool = True
    policy_reason: str | None = None

    event_start: datetime | None = None
    event_end: datetime | None = None

    privacy_mode: PrivacyMode = PrivacyMode.RAW
    engine_version: str = "3.1"
    configuration_version: str = "1.0"

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def validate_finding_evidence(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("finding evidence_ids must be unique")

        return value

    @field_validator("cross_tenant")
    @classmethod
    def validate_cross_tenant(
        cls,
        value: bool,
        info: Any,
    ) -> bool:
        tenant_ids = info.data.get("tenant_ids")

        if tenant_ids:
            actually_cross_tenant = len(set(tenant_ids)) > 1

            if value != actually_cross_tenant:
                raise ValueError(
                    "cross_tenant must equal whether more than one tenant "
                    "is represented by tenant_ids"
                )

        return value

    @field_validator("causal_relationship_ids")
    @classmethod
    def validate_causal_relationship_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError(
                "causal_relationship_ids must be unique"
            )

        return value


# ============================================================================
# Phase 4: Evidence graph models
# ============================================================================

class GraphNodeType(str, Enum):
    """Types of nodes represented in an evidence graph."""

    EVENT = "event"
    ENTITY = "entity"
    TENANT = "tenant"
    PROJECT = "project"
    INSTANCE = "instance"
    RESOURCE = "resource"
    FINDING = "finding"


class GraphEdgeType(str, Enum):
    """Semantic relationships represented by graph edges."""

    OCCURRED_IN = "occurred_in"
    INVOLVES_ENTITY = "involves_entity"
    TARGETS_RESOURCE = "targets_resource"
    ENTITY_RELATIONSHIP = "entity_relationship"
    CORRELATED_WITH = "correlated_with"
    REQUIRES = "requires"
    PROVIDES = "provides"
    ENABLES = "enables"
    SUPPORTS_FINDING = "supports_finding"


class EvidenceGraphNode(BaseModel):
    """A graph node with a stable identifier and traceable metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Field(..., min_length=1)
    node_type: GraphNodeType
    label: str = Field(..., min_length=1)
    tenant_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    attributes: dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    """A directed graph edge with explicit semantic meaning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edge_id: str = Field(..., min_length=1)
    source_node_id: str = Field(..., min_length=1)
    edge_type: GraphEdgeType
    target_node_id: str = Field(..., min_length=1)
    evidence_ids: tuple[str, ...] = ()
    tenant_ids: tuple[str, ...] = ()
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceGraph(BaseModel):
    """Graph view of the evidence supporting an analysis's findings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    analysis_id: str = Field(..., min_length=1)
    nodes: tuple[EvidenceGraphNode, ...] = ()
    edges: tuple[EvidenceGraphEdge, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


# ============================================================================
# Correlation result
# ============================================================================

class CorrelationResult(BaseModel):
    """
    Complete result of a correlation analysis.

    The causal statistics describe both execution and the final findings.
    Final finding and relationship counts must agree with the returned
    deduplicated findings.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    analysis_id: str = Field(..., min_length=1)
    started_at: datetime
    completed_at: datetime

    context: CorrelationContext
    findings: tuple[CorrelationFinding, ...] = ()

    evidence_count: int = Field(default=0, ge=0)
    candidate_count: int = Field(default=0, ge=0)
    evaluated_candidate_count: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    rejected_candidate_count: int = Field(default=0, ge=0)
    policy_denied_count: int = Field(default=0, ge=0)

    # ------------------------------------------------------------------
    # Phase 3: causal reasoning statistics
    # ------------------------------------------------------------------

    causal_candidate_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of scored candidates submitted to causal reasoning."
        ),
    )

    causal_evaluated_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of candidates actually evaluated by the causal reasoner."
        ),
    )

    causal_finding_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of final findings containing at least one causal "
            "relationship."
        ),
    )

    causal_relationship_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Total number of causal relationships attached to final findings."
        ),
    )

    # Phase 4: graph constructed from policy-approved findings.
    evidence_graph: EvidenceGraph | None = None

    # ------------------------------------------------------------------
    # Performance
    # ------------------------------------------------------------------

    duration_seconds: float = Field(default=0.0, ge=0.0)
    naive_comparison_count: int = Field(default=0, ge=0)

    candidate_reduction_ratio: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    provenance_reference_count: int = Field(default=0, ge=0)
    provenance_complete: bool = False

    # ------------------------------------------------------------------
    # Privacy
    # ------------------------------------------------------------------

    privacy_mode: PrivacyMode
    features_available: tuple[str, ...] = ()

    evidence_graph=evidence_graph,
    # ------------------------------------------------------------------
    # Execution metadata
    # ------------------------------------------------------------------

    engine_version: str = "3.1"
    configuration_version: str = "1.0"
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("completed_at")
    @classmethod
    def validate_completion_time(
        cls,
        value: datetime,
        info: Any,
    ) -> datetime:
        started_at = info.data.get("started_at")

        if started_at is not None and value < started_at:
            raise ValueError(
                "completed_at cannot be earlier than started_at"
            )

        return value

    @field_validator("analysis_id")
    @classmethod
    def validate_analysis_id(
        cls,
        value: str,
        info: Any,
    ) -> str:
        context = info.data.get("context")

        if context is not None and value != context.analysis_id:
            raise ValueError(
                "CorrelationResult.analysis_id must equal "
                "CorrelationContext.analysis_id"
            )

        return value

    @field_validator("finding_count")
    @classmethod
    def validate_finding_count(
        cls,
        value: int,
        info: Any,
    ) -> int:
        findings = info.data.get("findings")

        if findings is not None and value != len(findings):
            raise ValueError(
                "finding_count must equal the number of findings"
            )

        return value

    @field_validator("causal_finding_count")
    @classmethod
    def validate_causal_finding_count(
        cls,
        value: int,
        info: Any,
    ) -> int:
        findings = info.data.get("findings")

        if findings is not None:
            expected = sum(
                1
                for finding in findings
                if finding.causal_relationships
            )

            if value != expected:
                raise ValueError(
                    "causal_finding_count must equal the number of "
                    "findings containing causal relationships"
                )

        return value

    @field_validator("causal_relationship_count")
    @classmethod
    def validate_causal_relationship_count(
        cls,
        value: int,
        info: Any,
    ) -> int:
        findings = info.data.get("findings")

        if findings is not None:
            calculated = sum(
                len(finding.causal_relationships)
                for finding in findings
            )

            if value != calculated:
                raise ValueError(
                    "causal_relationship_count must equal the total number "
                    "of causal relationships attached to findings"
                )

        return value

CorrelationCandidate.model_rebuild()