# correlation/normaliser.py

from __future__ import annotations

from typing import Any

from correlation.models import CanonicalEvidence, EvidenceLayer


class EvidenceNormaliser:
    """
    Converts authoritative evidence records into the canonical representation
    used by the correlation layer.

    The normaliser does not modify, delete, or replace the original evidence.
    """

    def normalise_event(self, event: Any) -> CanonicalEvidence:
        """
        Normalise an instance EvidenceEvent.

        Source:
            evidence_events

        EvidenceEvent already contains an event timestamp, so both
        event_timestamp and collected_at can be populated from the source
        event metadata.
        """

        return CanonicalEvidence(
            evidence_id=event.event_id,
            tenant_id=event.tenant_id,
            # In the current prototype, tenant_id and the Incus project
            # identifier are equivalent for instance-level evidence.
            project_id=event.tenant_id,
            instance_name=event.instance_name,
            layer=EvidenceLayer.INSTANCE,
            evidence_type=self._enum_value(event.evidence_type),
            event_type=self._enum_value(event.event_type),
            source=event.source,
            source_path=event.source_path,
            event_timestamp=event.timestamp,
            collected_at=event.created_at,
            actor=event.actor,
            uid=event.uid,
            resource=event.resource,
            attributes=dict(event.details),
            raw_data=event.raw_data,
            sha256=event.sha256,
            agent_id=event.agent_id,
            sequence_start=event.sequence,
            sequence_end=event.sequence,
            provenance={
                "source_table": "evidence_events",
            },
        )

    def normalise_record(self, record: Any) -> CanonicalEvidence:
        """
        Normalise an authoritative host EvidenceRecord.

        Source:
            evidence_records

        Host records currently contain collection time but do not have a
        separately parsed event timestamp. Therefore event_timestamp is
        intentionally left as None.

        The original audit data remains available in raw_data and can be
        parsed later by a dedicated host-event parser.
        """

        return CanonicalEvidence(
            evidence_id=record.evidence_id,
            tenant_id=record.tenant_id,
            project_id=record.project_id,
            instance_name=record.instance_name,
            layer=EvidenceLayer.HOST,
            evidence_type="FORENSIC_RECORD",
            event_type="AUDIT",
            source=record.source,
            source_path=record.source_path,
            # Do not incorrectly treat collection time as event time.
            event_timestamp=None,
            collected_at=record.collected_at,
            attributes={},
            raw_data=record.raw_data,
            sha256=record.sha256,
            sequence_start=record.sequence_start,
            sequence_end=record.sequence_end,
            provenance={
                "source_table": "evidence_records",
                "acquisition_layer": record.acquisition_layer,
                "acquired_from": record.acquired_from,
                "attribution_method": record.attribution_method,
                "capture_id": record.capture_id,
                "record_sha256": record.record_sha256,
                "tenant_hash": record.tenant_hash,
                "scope": record.scope,
            },
        )

    @staticmethod
    def _enum_value(value):
        return value.value if hasattr(value, "value") else str(value)
