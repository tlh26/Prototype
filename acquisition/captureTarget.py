from __future__ import annotations

from dataclasses import dataclass

from evidence.tenant import TenantContext


@dataclass(frozen=True)
class CaptureTarget:
    """
    Identifies the exact tenant and instance from which
    evidence should be acquired.
    """

    tenant: TenantContext
    instance_name: str

    def __post_init__(self) -> None:
        if not self.instance_name.strip():
            raise ValueError("instance_name must not be empty")

    @property
    def tenant_id(self) -> str:
        return self.tenant.tenant_id

    @property
    def project_id(self) -> str:
        return self.tenant.platform_project_id
