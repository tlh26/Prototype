# correlation/engine.py

from __future__ import annotations

from dataclasses import dataclass

from correlation.correlationFinding import CorrelationFinding
from correlation.models import (
    CanonicalEvidence,
    EvidenceEntity,
    EvidenceRelationship,
)


@dataclass(frozen=True)
class CorrelationResult:
    """
    Complete derived result produced by the correlation engine.

    The original evidence remains authoritative in the central evidence
    store. This object contains only derived correlation structures and
    references back to the original evidence through their identifiers.
    """

    evidence: tuple[CanonicalEvidence, ...]
    entities: tuple[EvidenceEntity, ...]
    relationships: tuple[EvidenceRelationship, ...]
    findings: tuple[CorrelationFinding, ...]


class CorrelationEngine:
    """
    Orchestrates the correlation pipeline.

    The engine coordinates normalization, attribute extraction, entity
    extraction, relationship mapping, and deterministic correlation rules.
    Individual algorithms remain implemented in their respective
    components.
    """

    def __init__(
        self,
        normaliser,
        attribute_extractor,
        entity_mapper,
        relationship_mapper,
        rules,
    ):
        self.normaliser = normaliser
        self.attribute_extractor = attribute_extractor
        self.entity_mapper = entity_mapper
        self.relationship_mapper = relationship_mapper
        self.rules = tuple(rules)

    def normalise(self, evidence) -> CanonicalEvidence:
        """
        Convert one authoritative evidence item into canonical evidence.
        """

        if hasattr(evidence, "event_id"):
            return self.normaliser.normalise_event(evidence)

        return self.normaliser.normalise_record(evidence)

    def process(
        self,
        evidence_items,
    ) -> CorrelationResult:
        """
        Execute the complete correlation pipeline.

        Pipeline:

            authoritative evidence
                    ↓
              normalization
                    ↓
            attribute extraction
                    ↓
             entity extraction
                    ↓
           relationship mapping
                    ↓
          deterministic rules
                    ↓
                 result
        """

        canonical: list[CanonicalEvidence] = []
        entities: list[EvidenceEntity] = []
        relationships: list[EvidenceRelationship] = []

        # --------------------------------------------------------------
        # 1. Normalize and derive entity/relationship information
        # --------------------------------------------------------------
        for evidence in evidence_items:
            item = self.normalise(evidence)

            # Extracting the attributes creates the analytical attribute
            # view. The canonical evidence itself remains immutable.
            self.attribute_extractor.extract(item)

            canonical.append(item)

            item_entities = self.entity_mapper.extract(item)
            entities.extend(item_entities)

            item_relationships = self.relationship_mapper.map(
                item,
                item_entities,
            )
            relationships.extend(item_relationships)

        # --------------------------------------------------------------
        # 2. Evaluate deterministic correlation rules
        # --------------------------------------------------------------
        findings: list[CorrelationFinding] = []

        # Compare each pair exactly once.
        for index, first in enumerate(canonical):
            for second in canonical[index + 1 :]:
                for rule in self.rules:
                    finding = rule.evaluate(first, second)

                    if finding is not None:
                        findings.append(finding)

        # --------------------------------------------------------------
        # 3. Deduplicate derived structures
        # --------------------------------------------------------------
        return CorrelationResult(
            evidence=tuple(canonical),
            entities=self._deduplicate_entities(entities),
            relationships=self._deduplicate_relationships(relationships),
            findings=self._deduplicate_findings(findings),
        )

    @staticmethod
    def _deduplicate_entities(
        entities: list[EvidenceEntity],
    ) -> tuple[EvidenceEntity, ...]:
        """
        Deduplicate entities by their stable entity ID.

        If the same entity occurs in multiple evidence items, merge the
        evidence references rather than creating duplicate entities.
        """

        grouped: dict[str, EvidenceEntity] = {}

        for entity in entities:
            existing = grouped.get(entity.entity_id)

            if existing is None:
                grouped[entity.entity_id] = entity
                continue

            evidence_ids = tuple(
                dict.fromkeys(existing.evidence_ids + entity.evidence_ids)
            )

            grouped[entity.entity_id] = existing.model_copy(
                update={
                    "evidence_ids": evidence_ids,
                }
            )

        return tuple(grouped.values())

    @staticmethod
    def _deduplicate_relationships(
        relationships: list[EvidenceRelationship],
    ) -> tuple[EvidenceRelationship, ...]:
        """
        Deduplicate relationships while preserving all supporting evidence.
        """

        grouped: dict[str, EvidenceRelationship] = {}

        for relationship in relationships:
            existing = grouped.get(relationship.relationship_id)

            if existing is None:
                grouped[relationship.relationship_id] = relationship
                continue

            evidence_ids = tuple(
                dict.fromkeys(existing.evidence_ids + relationship.evidence_ids)
            )

            grouped[relationship.relationship_id] = relationship.model_copy(
                update={
                    "evidence_ids": evidence_ids,
                }
            )

        return tuple(grouped.values())

    @staticmethod
    def _deduplicate_findings(
        findings: list[CorrelationFinding],
    ) -> tuple[CorrelationFinding, ...]:
        """
        Deduplicate findings using their deterministic finding IDs.
        """

        unique: dict[str, CorrelationFinding] = {}

        for finding in findings:
            unique[finding.finding_id] = finding

        return tuple(unique.values())
