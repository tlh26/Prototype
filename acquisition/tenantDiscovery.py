from contextlib import contextmanager
from typing import Generator

from common.context import tenant_scope
from evidence.tenant import TenantContext
from acquisition.collectors.incus import IncusClient
from acquisition.tenantResolver import TenantResolver


class TenantDiscoveryService:

    def __init__(
        self,
        incus_client: IncusClient,
        tenant_resolver: TenantResolver,
    ) -> None:
        self.incus_client = incus_client
        self.tenant_resolver = tenant_resolver

    def discover_tenants(self) -> list[TenantContext]:
        projects = self.incus_client.list_projects()

        return [
            self.tenant_resolver.resolve_incus_project(project_id=project)
            for project in projects
        ]

    @contextmanager
    def tenant_scope_for_project(
        self,
        project_id: str,
    ) -> Generator[TenantContext, None, None]:

        tenant = self.tenant_resolver.resolve_incus_project(project_id=project_id)

        with tenant_scope(tenant):
            yield tenant
