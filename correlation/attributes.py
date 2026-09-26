# correlation/attributes.py

from __future__ import annotations

from datetime import datetime
from typing import Any

from correlation.models import CanonicalEvidence


class AttributeExtractor:
    """
    Extracts correlation attributes from canonical evidence.

    The extractor does not modify the CanonicalEvidence object and does not
    perform correlation. It only exposes normalized values that later
    components can use for entity extraction and rule evaluation.
    """

    def extract(
        self,
        evidence: CanonicalEvidence,
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}

        # ------------------------------------------------------------
        # Tenant / platform context
        # ------------------------------------------------------------

        if evidence.tenant_id is not None:
            attributes["tenant_id"] = evidence.tenant_id

        if evidence.project_id is not None:
            attributes["project_id"] = evidence.project_id

        if evidence.instance_name is not None:
            attributes["instance_name"] = evidence.instance_name

        # ------------------------------------------------------------
        # Actor / identity
        # ------------------------------------------------------------

        if evidence.actor is not None:
            attributes["actor"] = evidence.actor

        if evidence.uid is not None:
            attributes["uid"] = evidence.uid

        # ------------------------------------------------------------
        # Resource
        # ------------------------------------------------------------

        if evidence.resource is not None:
            attributes["resource"] = evidence.resource

        # ------------------------------------------------------------
        # Evidence classification
        # ------------------------------------------------------------

        attributes["source"] = evidence.source
        attributes["event_type"] = evidence.event_type
        attributes["evidence_type"] = evidence.evidence_type
        attributes["layer"] = evidence.layer.value

        if evidence.source_path is not None:
            attributes["source_path"] = evidence.source_path

        # ------------------------------------------------------------
        # Temporal attributes
        # ------------------------------------------------------------

        if evidence.event_timestamp is not None:
            attributes["event_timestamp"] = evidence.event_timestamp

        attributes["collected_at"] = evidence.collected_at

        # ------------------------------------------------------------
        # Sequence information
        # ------------------------------------------------------------

        if evidence.sequence_start is not None:
            attributes["sequence_start"] = evidence.sequence_start

        if evidence.sequence_end is not None:
            attributes["sequence_end"] = evidence.sequence_end

        # ------------------------------------------------------------
        # Agent information
        # ------------------------------------------------------------

        if evidence.agent_id is not None:
            attributes["agent_id"] = evidence.agent_id

        # ------------------------------------------------------------
        # Source-specific attributes
        # ------------------------------------------------------------

        # Source-specific attributes are deliberately added last.
        #
        # This allows the source evidence to contribute fields such as:
        # username, command, path, HTTP method, status code, IP address, etc.
        #
        # Do not allow source-specific data to silently overwrite the
        # canonical fields above.
        for key, value in evidence.attributes.items():
            if key not in attributes:
                attributes[key] = value

        return attributes
