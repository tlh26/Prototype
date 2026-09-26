# correlation/relationships.py

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict

from correlation.models import CanonicalEvidence, EvidenceEntity, EntityType


class RelationshipType(str, Enum):
    BELONGS_TO = "belongs_to"
    OCCURRED_ON = "occurred_on"
    ACTED_ON = "acted_on"
    REFERENCES = "references"
    CORRELATES_WITH = "correlates_with"


class EvidenceRelationship(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    relationship_id: str

    source_entity_id: str
    relationship_type: RelationshipType
    target_entity_id: str

    evidence_ids: tuple[str, ...] = ()


class RelationshipMapper:
    """
    Builds deterministic relationships between entities associated with
    canonical evidence.

    This component does not decide whether two evidence items constitute
    a forensic correlation. That is the responsibility of rules.py.
    """

    def map(
        self,
        evidence: CanonicalEvidence,
        entities: tuple[EvidenceEntity, ...],
    ) -> tuple[EvidenceRelationship, ...]:

        relationships: list[EvidenceRelationship] = []

        by_type = {entity.entity_type: entity for entity in entities}

        tenant = by_type.get(EntityType.TENANT)
        project = by_type.get(EntityType.PROJECT)
        instance = by_type.get(EntityType.INSTANCE)
        user = by_type.get(EntityType.USER)
        resource = by_type.get(EntityType.RESOURCE)

        # tenant -> project
        if tenant and project:
            relationships.append(
                self._relationship(
                    tenant,
                    RelationshipType.BELONGS_TO,
                    project,
                    evidence.evidence_id,
                )
            )

        # instance -> tenant
        if instance and tenant:
            relationships.append(
                self._relationship(
                    instance,
                    RelationshipType.BELONGS_TO,
                    tenant,
                    evidence.evidence_id,
                )
            )

        # evidence/user -> instance
        if user and instance:
            relationships.append(
                self._relationship(
                    user,
                    RelationshipType.ACTED_ON,
                    instance,
                    evidence.evidence_id,
                )
            )

        # evidence/resource -> instance
        if resource and instance:
            relationships.append(
                self._relationship(
                    resource,
                    RelationshipType.OCCURRED_ON,
                    instance,
                    evidence.evidence_id,
                )
            )

        return tuple(relationships)

    @staticmethod
    def _relationship(
        source: EvidenceEntity,
        relationship_type: RelationshipType,
        target: EvidenceEntity,
        evidence_id: str,
    ) -> EvidenceRelationship:

        canonical = (
            f"{source.entity_id}|" f"{relationship_type.value}|" f"{target.entity_id}"
        )

        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        return EvidenceRelationship(
            relationship_id=f"relationship:{digest}",
            source_entity_id=source.entity_id,
            relationship_type=relationship_type,
            target_entity_id=target.entity_id,
            evidence_ids=(evidence_id,),
        )
