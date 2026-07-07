"""Azure DevOps project, repo, and pipeline extractor."""
from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import structlog

from src.extractors.base import ExtractResult
from src.utils.id_generator import generate_surrogate_key
from src.utils.pagination import paginate_rest

logger = structlog.get_logger(__name__)

DEVOPS_API_BASE = "https://dev.azure.com"


class DevOpsExtractor:
    """Extracts Azure DevOps organizations, projects, repos, and pipelines.

    Uses PAT-based authentication (Base64-encoded) or OAuth bearer token.

    Args:
        org_name: Azure DevOps organization name.
        pat: Personal Access Token (or OAuth token).
        tenant_id: Azure AD tenant ID.
        snapshot_id: Current snapshot ID.
        use_pat: If True, use PAT auth; otherwise Bearer token.
    """

    def __init__(
        self,
        org_name: str,
        pat: str,
        tenant_id: str,
        snapshot_id: int,
        use_pat: bool = True,
    ) -> None:
        self.org_name = org_name
        self.pat = pat
        self.tenant_id = tenant_id
        self.snapshot_id = snapshot_id
        self.use_pat = use_pat
        self.logger = structlog.get_logger(self.__class__.__name__)

    @property
    def headers(self) -> dict[str, str]:
        """Build auth headers for DevOps API."""
        if self.use_pat:
            encoded = base64.b64encode(f":{self.pat}".encode()).decode()
            return {
                "Authorization": f"Basic {encoded}",
                "Content-Type": "application/json",
            }
        else:
            return {
                "Authorization": f"Bearer {self.pat}",
                "Content-Type": "application/json",
            }

    async def extract(self) -> ExtractResult:
        """Extract projects, repos, and pipelines.

        Returns:
            ExtractResult with resources.
        """
        start_time = time.monotonic()
        resources: list[dict[str, Any]] = []
        errors: list[str] = []
        base_url = f"{DEVOPS_API_BASE}/{self.org_name}"

        async with httpx.AsyncClient(timeout=60.0) as client:
            # List projects
            try:
                projects_url = f"{base_url}/_apis/projects?api-version=7.1"
                async for page in paginate_rest(
                    client, projects_url, self.headers,
                    next_link_key="continuationToken",
                ):
                    for proj in page:
                        proj_resource = self._map_project(proj)
                        resources.append(proj_resource)

                        proj_id = proj.get("id", "")

                        # List repos for this project
                        try:
                            repos_url = f"{base_url}/{proj_id}/_apis/git/repositories?api-version=7.1"
                            resp = await client.get(repos_url, headers=self.headers)
                            resp.raise_for_status()
                            for repo in resp.json().get("value", []):
                                resources.append(
                                    self._map_repo(repo, proj_resource["resource_id"])
                                )
                        except Exception as e:
                            errors.append(f"Repos in {proj_id}: {e}")

                        # List pipelines
                        try:
                            pipes_url = f"{base_url}/{proj_id}/_apis/pipelines?api-version=7.1"
                            resp = await client.get(pipes_url, headers=self.headers)
                            resp.raise_for_status()
                            for pipe in resp.json().get("value", []):
                                resources.append(
                                    self._map_pipeline(pipe, proj_resource["resource_id"])
                                )
                        except Exception as e:
                            errors.append(f"Pipelines in {proj_id}: {e}")

                self.logger.info("devops_extracted", resources=len(resources))

            except Exception as e:
                errors.append(f"DevOps projects: {e}")
                self.logger.error("devops_extraction_failed", error=str(e))

        duration = time.monotonic() - start_time
        return ExtractResult(
            records=resources,
            errors=errors,
            record_count=len(resources),
            duration_seconds=duration,
            extractor_name="DevOpsExtractor",
        )

    def _map_project(self, proj: dict[str, Any]) -> dict[str, Any]:
        """Map DevOps project to DimResource."""
        proj_id = proj.get("id", "")
        return {
            "resource_id": generate_surrogate_key("devops", proj_id),
            "tenant_id": self.tenant_id,
            "resource_guid": proj_id,
            "resource_type": "DEVOPS_PROJECT",
            "name": proj.get("name", ""),
            "parent_id": None,
        }

    def _map_repo(self, repo: dict[str, Any], project_resource_id: int) -> dict[str, Any]:
        """Map DevOps repo to DimResource."""
        repo_id = repo.get("id", "")
        return {
            "resource_id": generate_surrogate_key("devops", repo_id),
            "tenant_id": self.tenant_id,
            "resource_guid": repo_id,
            "resource_type": "DEVOPS_REPO",
            "name": repo.get("name", ""),
            "parent_id": project_resource_id,
        }

    def _map_pipeline(self, pipe: dict[str, Any], project_resource_id: int) -> dict[str, Any]:
        """Map DevOps pipeline to DimResource."""
        pipe_id = str(pipe.get("id", ""))
        return {
            "resource_id": generate_surrogate_key("devops", pipe_id),
            "tenant_id": self.tenant_id,
            "resource_guid": pipe_id,
            "resource_type": "DEVOPS_PIPELINE",
            "name": pipe.get("name", ""),
            "parent_id": project_resource_id,
        }
