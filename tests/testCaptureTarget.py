from unittest.mock import Mock

import pytest

from acquisition.captureTarget import CaptureTarget


def test_capture_target_identifies_tenant_and_instance():

    tenant = Mock()

    tenant.tenant_id = "tenant-b"
    tenant.platform_project_id = "tenant-b"

    target = CaptureTarget(
        tenant=tenant,
        instance_name="web-b",
    )

    assert target.tenant_id == "tenant-b"
    assert target.project_id == "tenant-b"
    assert target.instance_name == "web-b"


def test_capture_target_rejects_empty_instance():

    tenant = Mock()

    with pytest.raises(ValueError):

        CaptureTarget(
            tenant=tenant,
            instance_name="",
        )
