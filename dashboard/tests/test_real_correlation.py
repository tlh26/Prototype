from __future__ import annotations

import os

import pytest

from dashboard.services.factory import (
    build_correlation_service,
)


@pytest.mark.skipif(
    os.getenv("RUN_REAL_CENTRAL") != "1",
    reason="real Central PostgreSQL test disabled",
)
def test_real_correlation_service():
    service = build_correlation_service()

    result = service.correlate(
        tenant_id="tenant-a",
        limit=20,
    )

    assert hasattr(result, "evidence")
    assert hasattr(result, "entities")
    assert hasattr(result, "relationships")
    assert hasattr(result, "findings")

    for finding in result.findings:
        assert finding.tenant_id == "tenant-a"

        for evidence_id in finding.evidence_ids:
            assert evidence_id

@pytest.mark.skipif(
    os.getenv("RUN_REAL_CENTRAL") != "1",
    reason="real Central PostgreSQL test disabled",
)
def test_real_correlation_is_tenant_scoped():
    service = build_correlation_service()

    tenant_a_result = service.correlate(
        tenant_id="tenant-a",
        limit=100,
    )

    tenant_b_result = service.correlate(
        tenant_id="tenant-b",
        limit=100,
    )

    for finding in tenant_a_result.findings:
        assert finding.tenant_id == "tenant-a"

    for finding in tenant_b_result.findings:
        assert finding.tenant_id == "tenant-b"