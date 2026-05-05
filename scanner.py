"""Orchestrates the scan across org or project scope."""

import json
import logging
from typing import Optional

from google.cloud import asset_v1, resourcemanager_v3
from google.api_core import exceptions as gcp_exceptions

from models import Finding
from checks.api_keys import check_api_keys
from checks.sa_keys import check_sa_keys
from checks.sa_permissions import check_sa_permissions
from checks.org_policies import check_org_policies

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(
        self,
        org_id: Optional[str],
        project_id: Optional[str],
        key_age_days: int,
        usage_days: int,
        suppress_google_sas: bool = False,
        all_sa_permissions: bool = False,
    ):
        self.org_id = org_id
        self.project_id = project_id
        self.key_age_days = key_age_days
        self.usage_days = usage_days
        self.suppress_google_sas = suppress_google_sas
        self.all_sa_permissions = all_sa_permissions

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        if self.org_id:
            scope = f"organizations/{self.org_id}"
            projects, num_to_id = self._list_projects(self.org_id)
            logger.info(f"Found {len(projects)} active projects in org {self.org_id}")
            findings.extend(check_org_policies(self.org_id))
        else:
            scope = f"projects/{self.project_id}"
            projects = [self.project_id]
            num_to_id = self._resolve_single_project(self.project_id)

        # API key scan covers the entire scope in one pass via Asset Inventory
        logger.info("Scanning API keys...")
        findings.extend(check_api_keys(scope, num_to_id))

        # Per-project checks
        for project_id in projects:
            logger.info(f"Scanning project: {project_id}")
            key_findings = check_sa_keys(project_id, self.key_age_days, self.usage_days)
            findings.extend(key_findings)

            perm_findings = check_sa_permissions(project_id, self.suppress_google_sas)
            if not self.all_sa_permissions:
                # Default: only surface permission issues for SAs that also have a key —
                # keyless SAs can't be used with leaked credentials so the risk is lower.
                sas_with_keys = {
                    f.details["sa_email"]
                    for f in key_findings
                    if f.check_name == "SA_KEY_INVENTORY"
                }
                perm_findings = [
                    f for f in perm_findings
                    if f.details.get("sa_email") in sas_with_keys
                ]
            findings.extend(perm_findings)

        return findings

    def _list_projects(self, org_id: str) -> tuple[list[str], dict[str, str]]:
        """List all active projects under the org via Cloud Asset Inventory.

        Using Asset Inventory instead of ResourceManager SearchProjects because
        SearchProjects only returns direct children — projects nested in folders
        are missed. Asset Inventory searches the full org hierarchy in one call.

        Returns (project_ids, {numeric_project_number: project_id}).
        """
        client = asset_v1.AssetServiceClient()
        projects: list[str] = []
        num_to_id: dict[str, str] = {}

        try:
            request = asset_v1.ListAssetsRequest(
                parent=f"organizations/{org_id}",
                asset_types=["cloudresourcemanager.googleapis.com/Project"],
                content_type=asset_v1.ContentType.RESOURCE,
            )
            for asset in client.list_assets(request=request):
                if not asset.resource or not asset.resource.data:
                    continue
                asset_dict = json.loads(type(asset).to_json(asset))
                data = asset_dict.get("resource", {}).get("data", {})

                project_id = data.get("projectId", "")
                if not project_id or data.get("lifecycleState") != "ACTIVE":
                    continue

                # asset.name = "//cloudresourcemanager.googleapis.com/projects/{number}"
                number = asset.name.split("/")[-1]
                projects.append(project_id)
                num_to_id[number] = project_id
                logger.debug(f"Mapped {number} → {project_id}")

        except gcp_exceptions.PermissionDenied as e:
            logger.warning(f"Permission denied listing projects for org {org_id}: {e}")

        return projects, num_to_id

    def _resolve_single_project(self, project_id: str) -> dict[str, str]:
        """Return {project_number: project_id} for a single project.

        get_project returns project.name in canonical numeric form ("projects/306419495665"),
        so split("/")[-1] gives the numeric string that matches asset name paths.
        """
        client = resourcemanager_v3.ProjectsClient()
        try:
            project = client.get_project(name=f"projects/{project_id}")
            # project.name is "projects/{numeric_id}" in canonical form
            number = project.name.split("/")[-1]
            logger.info(f"Resolved {project_id} → project number {number}")
            return {number: project.project_id}
        except Exception as e:
            logger.warning(f"Could not resolve project number for {project_id}: {e}")
            return {}
