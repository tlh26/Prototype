
# dashboard/services/correlationPresentation.py

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from correlation.models import CorrelationFinding, CorrelationResult


class CorrelationPresentationAdapter:
    """
    Convert authoritative correlation results into dashboard-friendly data.

    Responsibilities:
      - Preserve the engine's score and policy decisions.
      - Produce readable finding summaries.
      - Expose supported causal links.
      - Build a partial evidence/finding/causal graph for presentation.
      - Calculate display counts from the returned result.

    This adapter must not:
      - Execute SQL or fetch evidence.
      - Recalculate correlation scores.
      - Apply or bypass tenant authorisation.
      - Infer causal links independently of CausalReasoner.
    """

    def adapt(
        self,
        result: CorrelationResult,
        *,
        findings: Iterable[CorrelationFinding] | None = None,
        graph_finding_limit: int | None = 12,
        graph_edge_limit: int = 40,
    ) -> dict[str, Any]:
        """
        Adapt an authoritative correlation result for dashboard display.

        The complete result remains authoritative for aggregate metrics.
        The optional findings argument limits which findings are displayed.
        Graph limits affect presentation only, not correlation or policy.
        """
        selected_findings = tuple(
            result.findings if findings is None else findings
        )

        displayed_findings = tuple(
            self._finding(finding)
            for finding in selected_findings
        )

        if graph_finding_limit is not None:
            graph_finding_limit = max(0, graph_finding_limit)
            graph_findings = selected_findings[:graph_finding_limit]
        else:
            graph_findings = selected_findings

        graph = self._graph(
            result,
            findings=graph_findings,
            max_edges=graph_edge_limit,
        )

        # Deduplicate causal relationships by their authoritative IDs.
        causal_by_id = {
            link.relationship_id: link
            for finding in selected_findings
            for link in finding.causal_relationships
        }

        causal_links = tuple(causal_by_id.values())

        relation_counts = Counter(
            self._value(link.relation)
            for link in causal_links
        )

        # IMPORTANT: adapt() must return a dictionary. Without this return,
        # Python returns None and dashboard services cannot access metrics.
        return {
            "analysis": {
                "analysis_id": result.analysis_id,
                "started_at": result.started_at,
                "completed_at": result.completed_at,
                "duration_seconds": result.duration_seconds,
                "engine_version": result.engine_version,
                "configuration_version": result.configuration_version,
                "privacy_mode": self._value(result.privacy_mode),
            },
            "metrics": {
                # Aggregate counts describe the complete engine result,
                # not just the subset of findings displayed on this page.
                "evidence_count": result.evidence_count,
                "candidate_count": result.candidate_count,
                "evaluated_candidate_count": (
                    result.evaluated_candidate_count
                ),
                "finding_count": result.finding_count,
                "rejected_candidate_count": (
                    result.rejected_candidate_count
                ),
                "policy_denied_count": result.policy_denied_count,
                "entity_count": self._metadata_count(
                    result, "entity_count"
                ),
                "relationship_count": self._metadata_count(
                    result, "relationship_count"
                ),
                "causal_relationship_count": len(causal_links),
                "causal_relation_counts": dict(relation_counts),
                "duration_seconds": result.duration_seconds,
                "candidate_reduction_ratio": (
                    result.candidate_reduction_ratio
                ),
                "provenance_reference_count": (
                    result.provenance_reference_count
                ),
                "provenance_complete": result.provenance_complete,
            },
            "findings": displayed_findings,
            "graph": graph,
            "causal_relationships": tuple(
                self._causal_link(link)
                for link in causal_links
            ),
            "warnings": tuple(result.warnings),
        }

    def _finding(
        self,
        finding: CorrelationFinding,
    ) -> dict[str, Any]:
        """Convert a finding into a dashboard-friendly representation."""
        score = finding.score

        features = tuple(
            {
                "name": self._value(feature.feature_name),
                "value": feature.value,
                "weight": feature.weight,
                "contribution": feature.contribution,
                "explanation": feature.explanation,
            }
            for feature in score.features
        )

        return {
            "finding": finding,
            "finding_id": finding.finding_id,
            "candidate_id": finding.candidate_id,
            "analysis_id": finding.analysis_id,
            "status": self._value(finding.status),
            "severity": self._value(finding.severity),
            "score": {
                "value": score.value,
                "threshold": score.threshold,
                "passed": score.passed,
                "features": features,
                "scoring_method": score.scoring_method,
                "weight_sum": score.weight_sum,
                "valid_feature_count": score.valid_feature_count,
                "explanation": score.explanation,
                "interpretation": score.metadata.get(
                    "score_interpretation",
                    "Weighted evidential support; not a probability.",
                ),
            },
            "explanation": finding.explanation,
            "reason_codes": tuple(finding.reason_codes),
            "evidence_ids": tuple(finding.evidence_ids),
            "tenant_ids": tuple(finding.tenant_ids),
            "cross_tenant": finding.cross_tenant,
            "entity_ids": tuple(finding.entity_ids),
            "relationship_ids": tuple(finding.relationship_ids),
            "causal_relationships": tuple(
                self._causal_link(link)
                for link in finding.causal_relationships
            ),
            "graph_edge_id": finding.graph_edge_id,
            "policy_allowed": finding.policy_allowed,
            "policy_id": finding.policy_id,
            "policy_reason": finding.policy_reason,
            "privacy_mode": self._value(finding.privacy_mode),
            "event_start": finding.event_start,
            "event_end": finding.event_end,
            "provenance": tuple(finding.provenance),
            "metadata": dict(finding.metadata),
            "engine_version": finding.engine_version,
            "configuration_version": finding.configuration_version,
        }

    def _graph(
        self,
        result: CorrelationResult,
        *,
        findings: Iterable[CorrelationFinding] | None = None,
        max_edges: int = 40,
    ) -> dict[str, Any]:
        """
        Build a partial graph using relationships supported by the result.

        Nodes represent evidence and findings. Edges represent evidence
        supporting a finding and causal links returned by the engine.

        This is a presentation graph, not a replacement for the
        authoritative correlation or causal reasoning process.
        """
        selected_findings = tuple(
            result.findings if findings is None else findings
        )

        max_edges = max(0, max_edges)
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        edge_ids: set[str] = set()

        # Create evidence nodes before edges are constructed.
        for finding in selected_findings:
            for evidence_id in finding.evidence_ids:
                node_id = f"evidence:{evidence_id}"

                nodes.setdefault(
                    node_id,
                    {
                        "id": node_id,
                        "kind": "evidence",
                        "label": evidence_id,
                        "tenant_id": None,
                        "instance_name": None,
                        "layer": None,
                        "timestamp": None,
                    },
                )

        for finding in selected_findings:
            finding_node_id = f"finding:{finding.finding_id}"

            nodes[finding_node_id] = {
                "id": finding_node_id,
                "kind": "finding",
                "label": finding.finding_id,
                "severity": self._value(finding.severity),
                "score": finding.score.value,
                "status": self._value(finding.status),
            }

            # Connect evidence nodes to their finding.
            for evidence_id in finding.evidence_ids:
                evidence_node_id = f"evidence:{evidence_id}"

                if evidence_node_id not in nodes:
                    continue

                edge_id = (
                    f"supports:{evidence_id}:{finding.finding_id}"
                )

                if edge_id in edge_ids:
                    continue

                edge_ids.add(edge_id)

                if len(edges) >= max_edges:
                    continue

                edges.append(
                    {
                        "id": edge_id,
                        "source": evidence_node_id,
                        "target": finding_node_id,
                        "source_label": nodes[evidence_node_id]["label"],
                        "target_label": nodes[finding_node_id]["label"],
                        "kind": "supports",
                        "label": "supports finding",
                    }
                )

            # Add only causal links supplied by the correlation engine.
            for link in finding.causal_relationships:
                source = f"evidence:{link.source_evidence_id}"
                target = f"evidence:{link.target_evidence_id}"

                if source not in nodes or target not in nodes:
                    continue

                edge_id = f"causal:{link.relationship_id}"

                if edge_id in edge_ids:
                    continue

                edge_ids.add(edge_id)

                if len(edges) >= max_edges:
                    continue

                edges.append(
                    {
                        "id": edge_id,
                        "source": source,
                        "target": target,
                        "source_label": nodes[source]["label"],
                        "target_label": nodes[target]["label"],
                        "kind": "causal",
                        "label": self._value(link.relation).upper(),
                        "confidence": link.confidence,
                        "explanation": link.explanation,
                    }
                )

        return {
            "nodes": tuple(nodes.values()),
            "edges": tuple(edges),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "evidence_node_count": sum(
                node["kind"] == "evidence"
                for node in nodes.values()
            ),
            "finding_node_count": sum(
                node["kind"] == "finding"
                for node in nodes.values()
            ),
            "causal_edge_count": sum(
                edge["kind"] == "causal"
                for edge in edges
            ),
        }

    @staticmethod
    def _causal_link(link: Any) -> dict[str, Any]:
        """Convert an engine-provided causal relationship for display."""
        return {
            "relationship_id": link.relationship_id,
            "relation": CorrelationPresentationAdapter._value(
                link.relation
            ),
            "source_evidence_id": link.source_evidence_id,
            "target_evidence_id": link.target_evidence_id,
            "source_action": link.source_action,
            "target_action": link.target_action,
            "evidence_ids": tuple(link.evidence_ids),
            "tenant_ids": tuple(link.tenant_ids),
            "cross_tenant": link.cross_tenant,
            "temporal_delta_seconds": link.temporal_delta_seconds,
            "confidence": link.confidence,
            "explanation": link.explanation,
            "metadata": dict(link.metadata),
        }

    @staticmethod
    def _value(value: Any) -> str:
        """Render enum values without changing the underlying model."""
        return str(getattr(value, "value", value))

    @staticmethod
    def _metadata_count(
        result: CorrelationResult,
        key: str,
    ) -> int:
        """Read aggregate counts without assuming result collections exist."""
        metadata = getattr(result, "metadata", None)

        if metadata is None:
            return 0

        if isinstance(metadata, dict):
            value = metadata.get(key, 0)
        else:
            value = getattr(metadata, key, 0)

        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0
