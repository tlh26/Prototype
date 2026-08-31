# processing/audit_parser.py
from __future__ import annotations
import re
from dataclasses import dataclass
from collections import defaultdict


@dataclass(frozen=True)
class AuditRecord:

    record_type: str

    timestamp: str

    sequence: int

    fields: dict[str, str]


_AUDIT_HEADER = re.compile(
    r"^type=(?P<type>\S+)"
    r".*?"
    r"msg=audit\((?P<timestamp>[^:]+):"
    r"(?P<sequence>\d+)\)"
)


class AuditParser:

    def parse_line(
        self,
        line: str,
    ) -> AuditRecord | None:

        match = _AUDIT_HEADER.search(line)

        if not match:
            return None

        record_type = match.group("type")
        timestamp = match.group("timestamp")
        sequence = int(match.group("sequence"))

        fields = self._parse_fields(line)

        return AuditRecord(
            record_type=record_type,
            timestamp=timestamp,
            sequence=sequence,
            fields=fields,
        )

    @staticmethod
    def _parse_fields(
        line: str,
    ) -> dict[str, str]:

        fields: dict[str, str] = {}

        for token in line.split():
            if "=" not in token:
                continue

            key, value = token.split(
                "=",
                1,
            )

            fields[key] = value

        return fields

    def group_audit_records(
        self,
        records: list[AuditRecord],
    ) -> dict[int, list[AuditRecord]]:

        grouped = defaultdict(list)

        for record in records:
            grouped[record.sequence].append(record)

        return dict(grouped)