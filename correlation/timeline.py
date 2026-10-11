# correlation/timeline.py

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from correlation.models import CanonicalEvidence


@dataclass(frozen=True)
class TimelineEntry:
    evidence_id: str
    timestamp: datetime
    evidence: CanonicalEvidence


class EvidenceTimeline:

    def build(
        self,
        evidence: list[CanonicalEvidence],
    ) -> tuple[TimelineEntry, ...]:

        entries: list[TimelineEntry] = []

        for item in evidence:
            if item.event_timestamp is None:
                continue

            entries.append(
                TimelineEntry(
                    evidence_id=item.evidence_id,
                    timestamp=item.event_timestamp,
                    evidence=item,
                )
            )

        entries.sort(
            key=lambda entry: (
                entry.timestamp,
                entry.evidence_id,
            )
        )

        return tuple(entries)
