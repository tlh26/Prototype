from __future__ import annotations

import re
from dataclasses import dataclass


_INCUS_SUBJECT_RE = re.compile(
    rb"\bsubj=incus-(tenant-[a-z0-9-]+)_([a-z0-9-]+)_"
)


@dataclass(frozen=True)
class AuditAttribution:
    """
    Infrastructure-level attribution of an audit event.

    tenant_id:
        Incus project identifier.

    instance_id:
        Incus instance identifier.

    method:
        Attribution mechanism used.
    """

    tenant_id: str | None
    instance_id: str | None
    method: str


class IncusAuditAttributor:
    """
    Attribute Linux audit records to Incus projects and instances.

    Current mechanism:

        subj=incus-<project>_<instance>_...

    Example:

        subj=incus-tenant-b_web-b_...

    becomes:

        tenant_id   = tenant-b
        instance_id = web-b
    """

    def attribute(
        self,
        raw_data: bytes,
    ) -> AuditAttribution:
        match = _INCUS_SUBJECT_RE.search(
            raw_data
        )

        if not match:
            return AuditAttribution(
                tenant_id=None,
                instance_id=None,
                method="unattributed",
            )

        tenant_id = match.group(1).decode(
            "utf-8",
            errors="replace",
        )

        instance_id = match.group(2).decode(
            "utf-8",
            errors="replace",
        )

        return AuditAttribution(
            tenant_id=tenant_id,
            instance_id=instance_id,
            method="incus_subject",
        )