"""Orchestrates the scan across org or project scope."""

import json
import logging
from typing import Optional

from google.cloud import asset_v1, resourcemanager_v3
from google.api_core import exceptions as gcp_exceptions

from models import Finding, Severity
from checks.api_keys import check_api_keys, AI_APIS
from checks.sa_keys import check_sa_keys
from checks.sa_permissions import check_sa_permissions
from checks.org_policies import check_org_policies
from checks.enabled_ai_apis import check_enabled_ai_apis

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

            logger.info(f"Checking enabled AI APIs in project: {project_id}")
            findings.extend(check_enabled_ai_apis(project_id))

        # Cross-correlate enabled AI APIs with API key findings to surface elevated risks
        findings.extend(self._correlate_ai_api_risks(findings))

        return findings

    def _correlate_ai_api_risks(self, all_findings: list[Finding]) -> list[Finding]:
        """Produce elevated findings when enabled AI APIs meet risky API key configurations.

        Two patterns are flagged:
        1. An unrestricted key (no API scope) in a project where Gemini/Vertex is enabled —
           that key silently grants access to the AI API to whoever holds it.
        2. A key explicitly scoped for an AI API plus other non-AI APIs — a single leaked
           key exposes both AI access and unrelated services.
        """
        correlated: list[Finding] = []
        doc_url = "https://cloud.google.com/docs/authentication/api-keys-best-practices"

        # Build map: project_id -> set of enabled AI API names
        ai_enabled: dict[str, set[str]] = {}
        for f in all_findings:
            if f.check_name in ("GEMINI_API_ENABLED", "VERTEX_AI_API_ENABLED"):
                ai_enabled.setdefault(f.project_id, set()).add(f.details["api_name"])

        if not ai_enabled:
            return correlated

        # Avoid duplicating correlated findings if called more than once
        correlated_keys: set[tuple] = set()

        for f in all_findings:
            if f.project_id not in ai_enabled:
                continue
            enabled_apis = ai_enabled[f.project_id]

            # Pattern 1: unrestricted key in a project with enabled AI APIs
            if f.check_name == "API_KEY_NO_API_RESTRICTION":
                dedup = ("AI_API_UNSCOPED_KEY_RISK", f.resource_name)
                if dedup not in correlated_keys:
                    correlated_keys.add(dedup)
                    correlated.append(Finding(
                        severity=Severity.HIGH,
                        project_id=f.project_id,
                        resource_name=f.resource_name,
                        check_name="AI_API_UNSCOPED_KEY_RISK",
                        description=(
                            f'API key "{f.details.get("display_name")}" has no API restrictions, '
                            f"and {sorted(enabled_apis)} {'are' if len(enabled_apis) > 1 else 'is'} "
                            f'enabled in project "{f.project_id}". '
                            "This key can silently make Gemini/Vertex AI calls and incur charges."
                        ),
                        recommendation=(
                            "Restrict this key to the specific APIs it actually needs. "
                            "If AI usage is unintended for this key, also consider disabling "
                            "the AI API in this project to eliminate the risk entirely."
                        ),
                        doc_url=doc_url,
                        details={
                            **f.details,
                            "enabled_ai_apis": sorted(enabled_apis),
                        },
                    ))

            # Pattern 2: key scoped for AI API + other non-AI APIs (broad blast radius)
            elif f.check_name == "API_KEY_AI_SCOPE":
                ai_api = f.details.get("ai_api", "")
                all_apis = set(f.details.get("api_services", []))
                non_ai_apis = sorted(all_apis - AI_APIS)
                if non_ai_apis:
                    dedup = ("AI_API_BROAD_KEY_SCOPE", f.resource_name, ai_api)
                    if dedup not in correlated_keys:
                        correlated_keys.add(dedup)
                        correlated.append(Finding(
                            severity=Severity.HIGH,
                            project_id=f.project_id,
                            resource_name=f.resource_name,
                            check_name="AI_API_BROAD_KEY_SCOPE",
                            description=(
                                f'API key "{f.details.get("display_name")}" is scoped for '
                                f"{ai_api} (enabled in this project) plus other APIs: {non_ai_apis}. "
                                "A single leaked key exposes both AI access and those additional services."
                            ),
                            recommendation=(
                                "Create a dedicated key restricted solely to the AI API. "
                                "Move the other API calls to a separate key with appropriate restrictions."
                            ),
                            doc_url=doc_url,
                            details={
                                **f.details,
                                "enabled_ai_apis": sorted(enabled_apis),
                                "non_ai_apis": non_ai_apis,
                            },
                        ))

        return correlated

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
