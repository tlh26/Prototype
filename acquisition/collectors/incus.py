"""
Only collects.

    Class: IncusCollector
    It should retrieve: Incus metadata
                Instance state
                Instance lifecycle events
                Project information
                Network information
                Configuration changes
"""

import requests  # type: ignore


class IncusClient:
    """
    Minimal client for communicating with the Incus REST API.
    """

    def __init__(
        self,
        base_url: str,
        client_cert: str,
        client_key: str,
        verify_tls: bool = False,
    ) -> None:

        self.base_url = base_url.rstrip("/")
        self.client_cert = (client_cert, client_key)
        self.verify_tls = verify_tls

    def _get(self, endpoint: str) -> dict:
        response = requests.get(
            f"{self.base_url}{endpoint}",
            cert=self.client_cert,
            verify=self.verify_tls,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()

    def get_server_info(self) -> dict:
        return self._get("/1.0")

    def list_projects(self) -> list[str]:
        response = self._get("/1.0/projects")

        return response["metadata"]

    def get_project(self, project_name: str) -> dict:
        return self._get(f"/1.0/projects/{project_name}")
