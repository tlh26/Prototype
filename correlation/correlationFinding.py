# correlation/correlationFinding.py

from __future__ import annotations

"""
Backward-compatible correlation finding imports.

The authoritative correlation result models live in correlation.models.
This module remains so existing imports do not immediately break.
"""

from correlation.models import (
    CorrelationFinding,
    FindingSeverity,
    FindingStatus,
)

__all__ = [
    "CorrelationFinding",
    "FindingSeverity",
    "FindingStatus",
]