# correlation/graph.py
"""Build a provenance-preserving graph from approved correlation findings."""

from __future__ import annotations

from typing import Mapping, Sequence

from correlation.models import (
    CanonicalEvidence,
    CausalLink,
    CausalRelation,
    CorrelationFinding,
    EvidenceEntity,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    EvidenceRelationship,
    GraphEdgeType,
    GraphNodeType,
)


class EvidenceGraphBuilder:
    """Construct a deterministic graph from accepted correlation findings.

    The graph is a derived view. It does not replace authoritative evidence.

    Only evidence IDs referenced by the supplied findings are included.
    Callers must supply policy-approved findings, not raw candidates.
    """

    VERSION = "1.0"

    def build(
        self,
        *,
        analysis_id: str,
        evidence_by_id: Mapping[str, CanonicalEvidence],
        entities_by_evidence: Mapping[str, Sequence[EvidenceEntity]],
        relationships: Sequence[EvidenceRelationship],
        findings: Sequence[CorrelationFinding],
    ) -> EvidenceGraph:
        nodes: dict[str, EvidenceGraphNode] = {}
        edges: dict[str, EvidenceGraphEdge] = {}

        # This allowlist prevents unrelated or rejected evidence from
        # entering the graph merely because it was available to the engine.
        approved_evidence_ids = {
            evidence_id
            for finding in findings
            if finding.policy_allowed
            for evidence_id in finding.evidence_ids
            if evidence_id in evidence_by_id
        }

        if not approved_evidence_ids:
            return EvidenceGraph(
                analysis_id=analysis_id,
                metadata={
                    "builder_version": self.VERSION,
                    "evidence_count": 0,
                    "finding_count": 0,
                },
            )

        def add_node(node: EvidenceGraphNode) -> None:
            nodes.setdefault(node.node_id, node)

        def add_edge(edge: EvidenceGraphEdge) -> None:
            # Do not permit dangling edges.
            if (
                edge.source_node_id not in nodes
                or edge.target_node_id not in nodes
            ):
                return
            edges.setdefault(edge.edge_id, edge)

        # ------------------------------------------------------------------
        # 1. Event, tenant, project, instance, actor and resource nodes
        # ------------------------------------------------------------------
        for evidence_id in sorted(approved_evidence_ids):
            evidence = evidence_by_id[evidence_id]
            event_node_id = f"event:{evidence_id}"

            add_node(
                EvidenceGraphNode(
                    node_id=event_node_id,
                    node_type=GraphNodeType.EVENT,
                    label=evidence.event_type,
                    tenant_id=evidence.tenant_id,
                    evidence_ids=(evidence_id,),
                    attributes={
                        "evidence_type": evidence.evidence_type,
                        "layer": evidence.layer.value,
                        "source": evidence.source,
                        "source_path": evidence.source_path,
                        "event_timestamp": (
                            evidence.event_timestamp.isoformat()
                            if evidence.event_timestamp
                            else None
                        ),
                        "collected_at": evidence.collected_at.isoformat(),
                        "sha256": evidence.sha256,
                        "agent_id": evidence.agent_id,
                        "sequence_start": evidence.sequence_start,
                        "sequence_end": evidence.sequence_end,
                    },
                )
            )

            if evidence.tenant_id:
                tenant_node_id = f"tenant:{evidence.tenant_id}"
                add_node(
                    EvidenceGraphNode(
                        node_id=tenant_node_id,
                        node_type=GraphNodeType.TENANT,
                        label=evidence.tenant_id,
                        tenant_id=evidence.tenant_id,
                        evidence_ids=(evidence_id,),
                    )
                )
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:occurred-in:{evidence_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.OCCURRED_IN,
                        target_node_id=tenant_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(evidence.tenant_id,),
                    )
                )

            if evidence.project_id:
                project_node_id = f"project:{evidence.project_id}"
                add_node(
                    EvidenceGraphNode(
                        node_id=project_node_id,
                        node_type=GraphNodeType.PROJECT,
                        label=evidence.project_id,
                        tenant_id=evidence.tenant_id,
                        evidence_ids=(evidence_id,),
                    )
                )
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:project:{evidence_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.OCCURRED_IN,
                        target_node_id=project_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(evidence.tenant_id,)
                        if evidence.tenant_id else (),
                    )
                )

            if evidence.instance_name:
                instance_node_id = (
                    f"instance:{evidence.tenant_id or 'unknown'}:"
                    f"{evidence.instance_name}"
                )
                add_node(
                    EvidenceGraphNode(
                        node_id=instance_node_id,
                        node_type=GraphNodeType.INSTANCE,
                        label=evidence.instance_name,
                        tenant_id=evidence.tenant_id,
                        evidence_ids=(evidence_id,),
                    )
                )
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:instance:{evidence_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.OCCURRED_IN,
                        target_node_id=instance_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(evidence.tenant_id,)
                        if evidence.tenant_id else (),
                    )
                )

            if evidence.actor:
                actor_node_id = (
                    f"entity:actor:{evidence.tenant_id or 'unknown'}:"
                    f"{evidence.actor}"
                )
                add_node(
                    EvidenceGraphNode(
                        node_id=actor_node_id,
                        node_type=GraphNodeType.ENTITY,
                        label=evidence.actor,
                        tenant_id=evidence.tenant_id,
                        evidence_ids=(evidence_id,),
                        attributes={"entity_kind": "actor"},
                    )
                )
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:actor:{evidence_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.INVOLVES_ENTITY,
                        target_node_id=actor_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(evidence.tenant_id,)
                        if evidence.tenant_id else (),
                    )
                )

            if evidence.resource:
                resource_node_id = (
                    f"resource:{evidence.tenant_id or 'unknown'}:"
                    f"{evidence.resource}"
                )
                add_node(
                    EvidenceGraphNode(
                        node_id=resource_node_id,
                        node_type=GraphNodeType.RESOURCE,
                        label=evidence.resource,
                        tenant_id=evidence.tenant_id,
                        evidence_ids=(evidence_id,),
                    )
                )
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:resource:{evidence_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.TARGETS_RESOURCE,
                        target_node_id=resource_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(evidence.tenant_id,)
                        if evidence.tenant_id else (),
                    )
                )

        # ------------------------------------------------------------------
        # 2. Extracted entities and entity relationships
        # ------------------------------------------------------------------
        for evidence_id in sorted(approved_evidence_ids):
            for entity in entities_by_evidence.get(evidence_id, ()):
                # Entity IDs are supplied by the extractor. Do not merge
                # tenant-scoped identities based on a display value alone.
                node_id = f"entity:{entity.entity_id}"
                add_node(
                    EvidenceGraphNode(
                        node_id=node_id,
                        node_type=(
                            GraphNodeType.TENANT
                            if entity.entity_type.value == "tenant"
                            else GraphNodeType.PROJECT
                            if entity.entity_type.value == "project"
                            else GraphNodeType.INSTANCE
                            if entity.entity_type.value == "instance"
                            else GraphNodeType.RESOURCE
                            if entity.entity_type.value == "resource"
                            else GraphNodeType.ENTITY
                        ),
                        label=entity.value,
                        tenant_id=entity.tenant_id,
                        evidence_ids=tuple(
                            sorted(
                                set(entity.evidence_ids)
                                & approved_evidence_ids
                            )
                        ) or (evidence_id,),
                        attributes={"entity_type": entity.entity_type.value},
                    )
                )

                event_node_id = f"event:{evidence_id}"
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:entity:{evidence_id}:{entity.entity_id}",
                        source_node_id=event_node_id,
                        edge_type=GraphEdgeType.INVOLVES_ENTITY,
                        target_node_id=node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=(entity.tenant_id,)
                        if entity.tenant_id else (),
                    )
                )

        for relationship in relationships:
            supporting_ids = (
                set(relationship.evidence_ids) & approved_evidence_ids
            )
            if not supporting_ids:
                continue

            source_id = f"entity:{relationship.source_entity_id}"
            target_id = f"entity:{relationship.target_entity_id}"

            if source_id not in nodes or target_id not in nodes:
                continue

            add_edge(
                EvidenceGraphEdge(
                    edge_id=f"edge:entity-relationship:{relationship.relationship_id}",
                    source_node_id=source_id,
                    edge_type=GraphEdgeType.ENTITY_RELATIONSHIP,
                    target_node_id=target_id,
                    evidence_ids=tuple(sorted(supporting_ids)),
                    metadata={
                        "relationship_type": (
                            relationship.relationship_type.value
                        ),
                        "relationship_id": relationship.relationship_id,
                    },
                )
            )

        # ------------------------------------------------------------------
        # 3. Findings and non-causal correlation edges
        # ------------------------------------------------------------------
        for finding in findings:
            if not finding.policy_allowed:
                continue

            evidence_ids = tuple(
                evidence_id
                for evidence_id in finding.evidence_ids
                if evidence_id in approved_evidence_ids
            )
            if not evidence_ids:
                continue

            finding_node_id = f"finding:{finding.finding_id}"
            add_node(
                EvidenceGraphNode(
                    node_id=finding_node_id,
                    node_type=GraphNodeType.FINDING,
                    label=finding.finding_id,
                    evidence_ids=evidence_ids,
                    attributes={
                        "candidate_id": finding.candidate_id,
                        "score": finding.score.value,
                        "severity": finding.severity.value,
                        "cross_tenant": finding.cross_tenant,
                        "privacy_mode": finding.privacy_mode.value,
                        "provenance_count": len(finding.provenance),
                    },
                )
            )

            # Each support edge explicitly connects the finding to the
            # event records that justify it.
            for evidence_id in evidence_ids:
                event_node_id = f"event:{evidence_id}"
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=(
                            f"edge:supports:{finding.finding_id}:{evidence_id}"
                        ),
                        source_node_id=finding_node_id,
                        edge_type=GraphEdgeType.SUPPORTS_FINDING,
                        target_node_id=event_node_id,
                        evidence_ids=(evidence_id,),
                        tenant_ids=finding.tenant_ids,
                        confidence=finding.score.value,
                        explanation=finding.explanation,
                    )
                )

            # CORRELATED_WITH means the scorer accepted a relationship;
            # it does not imply a causal relationship.
            if len(evidence_ids) >= 2:
                first_id, second_id = evidence_ids[:2]
                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:correlated:{finding.candidate_id}",
                        source_node_id=f"event:{first_id}",
                        edge_type=GraphEdgeType.CORRELATED_WITH,
                        target_node_id=f"event:{second_id}",
                        evidence_ids=evidence_ids,
                        tenant_ids=finding.tenant_ids,
                        confidence=finding.score.value,
                        explanation=finding.explanation,
                        metadata={
                            "candidate_id": finding.candidate_id,
                            "finding_id": finding.finding_id,
                            "causal": False,
                        },
                    )
                )

            # ----------------------------------------------------------------
            # 4. Causal edges: direction is taken from the causal reasoner.
            # ----------------------------------------------------------------
            relation_to_edge = {
                CausalRelation.REQUIRES: GraphEdgeType.REQUIRES,
                CausalRelation.PROVIDES: GraphEdgeType.PROVIDES,
                CausalRelation.ENABLES: GraphEdgeType.ENABLES,
            }

            for link in finding.causal_relationships:
                if not (
                    link.source_evidence_id in evidence_ids
                    and link.target_evidence_id in evidence_ids
                ):
                    continue

                add_edge(
                    EvidenceGraphEdge(
                        edge_id=f"edge:causal:{link.relationship_id}",
                        source_node_id=f"event:{link.source_evidence_id}",
                        edge_type=relation_to_edge[link.relation],
                        target_node_id=f"event:{link.target_evidence_id}",
                        evidence_ids=tuple(
                            evidence_id
                            for evidence_id in link.evidence_ids
                            if evidence_id in approved_evidence_ids
                        ),
                        tenant_ids=link.tenant_ids,
                        confidence=link.confidence,
                        explanation=link.explanation,
                        metadata={
                            "relationship_id": link.relationship_id,
                            "cross_tenant": link.cross_tenant,
                            "temporal_delta_seconds": (
                                link.temporal_delta_seconds
                            ),
                            "source_action": link.source_action,
                            "target_action": link.target_action,
                        },
                    )
                )

        return EvidenceGraph(
            analysis_id=analysis_id,
            nodes=tuple(nodes[key] for key in sorted(nodes)),
            edges=tuple(edges[key] for key in sorted(edges)),
            metadata={
                "builder_version": self.VERSION,
                "evidence_count": len(approved_evidence_ids),
                "finding_count": sum(
                    1 for finding in findings if finding.policy_allowed
                ),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "causal_edge_count": sum(
                    edge.edge_type in {
                        GraphEdgeType.REQUIRES,
                        GraphEdgeType.PROVIDES,
                        GraphEdgeType.ENABLES,
                    }
                    for edge in edges.values()
                ),
            },
        )
