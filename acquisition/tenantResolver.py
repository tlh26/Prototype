from common.hashing import HashingService
from evidence.enums import CloudPlatform
from evidence.tenant import TenantContext


class TenantResolver:
    """
    Resolves Incus Projects into TenantContext objects.

    In the prototype, each Incus Project represents exactly one
    logical tenant.
    """

    def __init__(self) -> None:
        self.hashing_service = HashingService()

    def resolve_incus_project(
        self,
        project_id: str,
        tenant_name: str | None = None,
        description: str | None = None,
    ) -> TenantContext:

        if not project_id or not project_id.strip():
            raise ValueError(
                "Incus project ID cannot be empty."
            )

        project_id = project_id.strip()

        if tenant_name is None:
            tenant_name = f"tenant-{project_id.split('-')[-1]}"

        canonical_identity = (
            f"incus:{project_id}"
        )

        tenant_hash = (
            self.hashing_service.sha256(
                canonical_identity
            )
        )

        return TenantContext(
            tenant_id=project_id,
            tenant_name=tenant_name,
            tenant_hash=tenant_hash,
            platform=CloudPlatform.INCUS,
            platform_project_id=project_id,
            description=description,
        )


