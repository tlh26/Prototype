# correlation/entities.py

from __future__ import annotations

import hashlib

from correlation.models import (
    CanonicalEvidence,
    EntityType,
    EvidenceEntity,
)


class EntityExtractor:
    """
    Deterministically extracts entities from canonical evidence.

    Entity identifiers are stable for the same logical entity and are
    independent of the evidence record that caused the entity to be observed.
    """

    def extract(
        self,
        evidence: CanonicalEvidence,
    ) -> tuple[EvidenceEntity, ...]:
        entities: list[EvidenceEntity] = []

        # ------------------------------------------------------------
        # Tenant
        # ------------------------------------------------------------

        if evidence.tenant_id:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.TENANT,
                    value=evidence.tenant_id,
                    tenant_id=evidence.tenant_id,
                    evidence_id=evidence.evidence_id,
                )
            )

        # ------------------------------------------------------------
        # Project
        # ------------------------------------------------------------

        if evidence.project_id:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.PROJECT,
                    value=evidence.project_id,
                    tenant_id=evidence.tenant_id,
                    evidence_id=evidence.evidence_id,
                )
            )

        # ------------------------------------------------------------
        # Instance
        # ------------------------------------------------------------

        if evidence.instance_name:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.INSTANCE,
                    value=evidence.instance_name,
                    tenant_id=evidence.tenant_id,
                    instance_name=evidence.instance_name,
                    evidence_id=evidence.evidence_id,
                )
            )

        # ------------------------------------------------------------
        # Actor / user
        # ------------------------------------------------------------

        if evidence.actor:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.USER,
                    value=evidence.actor,
                    tenant_id=evidence.tenant_id,
                    instance_name=evidence.instance_name,
                    evidence_id=evidence.evidence_id,
                )
            )

        # ------------------------------------------------------------
        # Resource
        # ------------------------------------------------------------

        if evidence.resource:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.RESOURCE,
                    value=evidence.resource,
                    tenant_id=evidence.tenant_id,
                    instance_name=evidence.instance_name,
                    evidence_id=evidence.evidence_id,
                )
            )

        # ------------------------------------------------------------
        # Process
        # ------------------------------------------------------------

        process = evidence.attributes.get("process")

        if process:
            entities.append(
                self._build_entity(
                    entity_type=EntityType.PROCESS,
                    value=str(process),
                    tenant_id=evidence.tenant_id,
                    instance_name=evidence.instance_name,
                    evidence_id=evidence.evidence_id,
                )
            )

        return tuple(entities)

    def _build_entity(
        self,
        *,
        entity_type: EntityType,
        value: str,
        tenant_id: str | None,
        evidence_id: str,
        instance_name: str | None = None,
    ) -> EvidenceEntity:
        entity_id = self._entity_id(
            entity_type=entity_type,
            value=value,
            tenant_id=tenant_id,
            instance_name=instance_name,
        )

        return EvidenceEntity(
            entity_id=entity_id,
            entity_type=entity_type,
            value=value,
            tenant_id=tenant_id,
            instance_name=instance_name,
            evidence_ids=(evidence_id,),
        )

    @staticmethod
    def _entity_id(
        *,
        entity_type: EntityType,
        value: str,
        tenant_id: str | None,
        instance_name: str | None,
    ) -> str:
        """
        Generate a deterministic entity identifier.

        Tenant context is included where available so that identical values
        belonging to different tenants do not collapse into one entity.
        """

        parts = [
            entity_type.value,
            tenant_id or "",
            instance_name or "",
            value,
        ]

        canonical = ":".join(parts)

        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        return f"{entity_type.value}:{digest}"
