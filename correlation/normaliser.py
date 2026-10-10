# correlation/normaliser.py
from __future__ import annotations
from typing import Any
from correlation.models import (
    CanonicalEvidence,
    EvidenceLayer,
)
from evidenceAgent.evidenceAgent.models import EvidenceEvent


class EvidenceNormaliser:
    """
    Converts authoritative evidence records into the canonical
    representation consumed by the correlation layer.

    The normaliser does not modify, delete, or replace the original
    authoritative evidence.
    """

    def normalise_event(
        self,
        event: EvidenceEvent,
    ) -> CanonicalEvidence:
        """
        Normalise an EvidenceAgent EvidenceEvent.

        Instance-agent evidence is represented as INSTANCE-layer evidence.
        The authoritative event fields are preserved in the canonical model,
        while additional acquisition metadata is retained in provenance.
        """

        return CanonicalEvidence(
            evidence_id=event.event_id,
            tenant_id=event.tenant_id,

            # EvidenceEvent does not carry a separate Incus project ID.
            # In the current architecture the tenant boundary is represented
            # by the Incus project, so tenant_id is used here.
            project_id=event.tenant_id,

            instance_name=event.instance_name,

            layer=EvidenceLayer.INSTANCE,

            evidence_type=event.evidence_type.value,
            event_type=event.event_type.value,

            source=event.source,
            source_path=event.source_path,

            # This is the occurrence/event timestamp, not merely collection
            # time. This distinction is important for temporal correlation.
            event_timestamp=event.timestamp,

            collected_at=event.created_at,

            actor=event.actor,
            uid=event.uid,
            resource=event.resource,

            # Preserve the agent's structured event details as attributes.
            attributes=dict(event.details),

            # Preserve the authoritative raw evidence.
            raw_data=event.raw_data,

            # SHA-256 supplied by EvidenceAgent.
            sha256=event.sha256,

            agent_id=event.agent_id,

            sequence_start=event.sequence,
            sequence_end=event.sequence,

            provenance={
                "source_table": "evidence",
                "acquisition_layer": "instance",
                "agent_id": event.agent_id,
                "sequence": event.sequence,
                "source": event.source,
                "source_path": event.source_path,
                "evidence_type": event.evidence_type.value,
                "event_type": event.event_type.value,
            },
        )

    def normalise_record(
        self,
        record: Any,
    ) -> CanonicalEvidence:
        """
        Normalise host-side evidence records.

        This method intentionally accepts Any because the host acquisition
        model is separate from EvidenceAgent.EvidenceEvent.

        Host audit evidence does not automatically receive an event timestamp
        here. Collection time and event occurrence time are different
        concepts, and the host acquisition layer should provide a trustworthy
        event timestamp before one is used for temporal correlation.
        """

        provenance = {
            "source_table": "evidence_records",
            "acquisition_layer": "host",
            "acquired_from": getattr(
                record,
                "acquired_from",
                None,
            ),
            "attribution_method": getattr(
                record,
                "attribution_method",
                None,
            ),
            "capture_id": getattr(
                record,
                "capture_id",
                None,
            ),
            "record_sha256": getattr(
                record,
                "sha256",
                None,
            ),
            "tenant_hash": getattr(
                record,
                "tenant_hash",
                None,
            ),
            "scope": getattr(
                record,
                "scope",
                None,
            ),
        }

        return CanonicalEvidence(
            evidence_id=record.evidence_id,
            tenant_id=record.tenant_id,
            project_id=record.project_id,
            instance_name=record.instance_name,

            layer=EvidenceLayer.HOST,

            evidence_type="forensic_record",
            event_type="audit",

            source=record.source,
            source_path=record.source_path,

            event_timestamp=None,

            collected_at=record.collected_at,

            actor=getattr(
                record,
                "actor",
                None,
            ),
            uid=getattr(
                record,
                "uid",
                None,
            ),
            resource=getattr(
                record,
                "resource",
                None,
            ),

            attributes={},

            raw_data=record.raw_data,
            sha256=record.sha256,

            agent_id=getattr(
                record,
                "agent_id",
                None,
            ),

            sequence_start=getattr(
                record,
                "sequence_start",
                getattr(
                    record,
                    "sequence",
                    None,
                ),
            ),

            sequence_end=getattr(
                record,
                "sequence_end",
                getattr(
                    record,
                    "sequence",
                    None,
                ),
            ),

            provenance=provenance,
        )

    def normalise(self, event: Any) -> CanonicalEvidence:
        if isinstance(event, CanonicalEvidence):
            return event

        if isinstance(event, EvidenceEvent):
            return self.normalise_event(event)

        return self.normalise_record(event)