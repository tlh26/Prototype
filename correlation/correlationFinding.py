# correlation/correlationFinding.py

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from correlation.models import FindingSeverity


class CorrelationFinding(BaseModel):
    """
    Derived result produced by a deterministic correlation rule.

    A finding references original evidence rather than replacing or
    duplicating the authoritative evidence.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    finding_id: str

    rule_id: str
    rule_version: str

    title: str
    description: str

    severity: FindingSeverity

    tenant_id: str | None = None

    entity_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None

    attributes: dict[str, str] = Field(default_factory=dict)

    created_at: datetime
