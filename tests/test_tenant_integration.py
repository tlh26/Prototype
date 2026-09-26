from acquisition.collectors.incus import IncusClient
from acquisition.tenantResolver import TenantResolver
from evidence.enums import CloudPlatform
import os
from dotenv import load_dotenv

load_dotenv()


def test_real_incus_projects_resolve_to_tenants_other():

    incus_client = IncusClient(
        base_url=os.environ["INCUS_BASE_URL"],
        client_cert=os.environ["INCUS_CLIENT_CERT"],
        client_key=os.environ["INCUS_CLIENT_KEY"],
        verify_tls=False,
    )

    resolver = TenantResolver()

    projects = incus_client.list_projects()

    tenants = [resolver.resolve_incus_project(project) for project in projects]

    assert len(tenants) == len(projects)

    for project, tenant in zip(projects, tenants):
        assert tenant.platform == CloudPlatform.INCUS
        assert tenant.tenant_id == project
        assert tenant.platform_project_id == project
