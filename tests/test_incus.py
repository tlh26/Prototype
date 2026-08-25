import os
from dotenv import load_dotenv
from acquisition.collectors.incus import IncusClient

load_dotenv()

def test_incus_server_is_reachable():

    client = IncusClient(
        base_url= os.environ["INCUS_BASE_URL"],
        client_cert= os.environ["INCUS_CLIENT_CERT"],
        client_key= os.environ["INCUS_CLIENT_KEY"],
        verify_tls=False,
    )

    response = client.get_server_info()

    assert response["type"] == "sync"
    assert response["status"] == "Success"


def test_incus_discovers_projects():
    
    client = IncusClient(
        base_url= os.environ["INCUS_BASE_URL"],
        client_cert= os.environ["INCUS_CLIENT_CERT"],
        client_key= os.environ["INCUS_CLIENT_KEY"],
        verify_tls=False,
    )

    projects = client.list_projects()

    assert isinstance(projects, list)
    assert len(projects) > 0


