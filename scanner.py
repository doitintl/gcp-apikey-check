"""Orchestrates the scan across org or project scope."""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from google.cloud import asset_v1
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from gcp_errors import SkipCollector, with_retry
from models import Finding, Severity
from scan_context import ScanContext
from checks.api_keys import check_api_keys, AI_APIS
from checks.sa_keys import check_sa_keys
from checks.sa_permissions import check_sa_permissions
from checks.org_policies import check_org_policies
from checks.enabled_ai_apis import check_enabled_ai_apis

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class ScanResult:
    """Everything a scan produced — findings plus the coverage needed to trust them."""
    findings: list[Finding]
    skips: SkipCollector
    scope: str
    projects_total: int
    max_workers: int
    duration_s: float


class Scanner:
    def __init__(
        self,
        org_id: Optional[str],
        project_id: Optional[str],
        key_age_days: int,
        usage_days: int,
        suppress_google_sas: bool = False,
        all_sa_permissions: bool = False,
        max_workers: int = 10,
    ):
        self.org_id = org_id
        self.project_id = project_id
        self.key_age_days = key_age_days
        self.usage_days = usage_days
        self.suppress_google_sas = suppress_google_sas
        self.all_sa_permissions = all_sa_permissions
        self.max_workers = max(1, max_workers)

    def run(self) -> ScanResult:
        start = time.perf_counter()
        ctx = ScanContext()
        findings: list[Finding] = []

        scope = f"organizations/{self.org_id}" if self.org_id else f"projects/{self.project_id}"

        # 1. Resolve the set of projects in scope.
        with console.status("[bold]Resolving projects in scope…", spinner="dots"):
            if self.org_id:
                projects, num_to_id = self._list_projects(ctx, self.org_id)
            else:
                assert self.project_id is not None  # argparse guarantees one of org/project
                projects = [self.project_id]
                num_to_id = self._resolve_single_project(ctx, self.project_id)
        console.print(f"  Scope: [bold]{scope}[/bold]  ·  {len(projects)} project(s)  ·  {self.max_workers} workers")

        # 2. Scope-wide checks — one Asset Inventory pass each, cheap regardless of size.
        with console.status("[bold]Scanning API keys, AI APIs, and org policies…", spinner="dots"):
            findings.extend(check_api_keys(ctx, scope, num_to_id))
            findings.extend(check_enabled_ai_apis(ctx, scope, num_to_id))
            if self.org_id:
                findings.extend(check_org_policies(ctx, self.org_id))

        # 3. Per-project checks (SA keys + permissions) — concurrent, with live ETA.
        if projects:
            findings.extend(self._scan_projects_concurrently(ctx, projects))

        # 4. Cross-correlate enabled AI APIs with risky API key configurations.
        findings.extend(self._correlate_ai_api_risks(findings))

        return ScanResult(
            findings=findings,
            skips=ctx.skips,
            scope=scope,
            projects_total=len(projects),
            max_workers=self.max_workers,
            duration_s=time.perf_counter() - start,
        )

    # ------------------------------------------------------------------ #
    # Per-project concurrency
    # ------------------------------------------------------------------ #

    def _scan_one_project(self, ctx: ScanContext, project_id: str) -> list[Finding]:
        """Run the per-project checks for a single project."""
        out: list[Finding] = []

        key_findings = check_sa_keys(ctx, project_id, self.key_age_days, self.usage_days)
        out.extend(key_findings)

        perm_findings = check_sa_permissions(ctx, project_id, self.suppress_google_sas)
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
        out.extend(perm_findings)
        return out

    def _scan_projects_concurrently(self, ctx: ScanContext, projects: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("·"),
            TimeElapsedColumn(),
            TextColumn("· ETA"),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        )
        with progress:
            task = progress.add_task("Scanning projects", total=len(projects))
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self._scan_one_project, ctx, p): p for p in projects}
                for future in as_completed(futures):
                    try:
                        findings.extend(future.result())
                    except Exception as exc:  # noqa: BLE001 — never let one project kill the scan
                        ctx.skips.record(f"projects/{futures[future]}", "project_scan", exc)
                    progress.advance(task)
        return findings

    # ------------------------------------------------------------------ #
    # Correlation
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # Project discovery
    # ------------------------------------------------------------------ #

    def _list_projects(self, ctx: ScanContext, org_id: str) -> tuple[list[str], dict[str, str]]:
        """List all active projects under the org via Cloud Asset Inventory.

        Using Asset Inventory instead of ResourceManager SearchProjects because
        SearchProjects only returns direct children — projects nested in folders
        are missed. Asset Inventory searches the full org hierarchy in one call.

        Returns (project_ids, {numeric_project_number: project_id}).
        """
        projects: list[str] = []
        num_to_id: dict[str, str] = {}

        request = asset_v1.ListAssetsRequest(
            parent=f"organizations/{org_id}",
            asset_types=["cloudresourcemanager.googleapis.com/Project"],
            content_type=asset_v1.ContentType.RESOURCE,
            page_size=500,
        )

        try:
            assets = with_retry(lambda: list(ctx.asset_client.list_assets(request=request)))
        except Exception as exc:  # noqa: BLE001
            ctx.skips.record(f"organizations/{org_id}", "list_projects", exc)
            return projects, num_to_id

        for asset in assets:
            if not asset.resource or not asset.resource.data:
                continue
            data = json.loads(type(asset).to_json(asset)).get("resource", {}).get("data", {})

            project_id = data.get("projectId", "")
            if not project_id or data.get("lifecycleState") != "ACTIVE":
                continue

            # asset.name = "//cloudresourcemanager.googleapis.com/projects/{number}"
            number = asset.name.split("/")[-1]
            projects.append(project_id)
            num_to_id[number] = project_id

        return projects, num_to_id

    def _resolve_single_project(self, ctx: ScanContext, project_id: str) -> dict[str, str]:
        """Return {project_number: project_id} for a single project.

        get_project returns project.name in canonical numeric form ("projects/306419495665"),
        so split("/")[-1] gives the numeric string that matches asset name paths.
        """
        try:
            project = with_retry(
                lambda: ctx.projects_client.get_project(name=f"projects/{project_id}")
            )
            number = project.name.split("/")[-1]
            return {number: project.project_id}
        except Exception as exc:  # noqa: BLE001
            ctx.skips.record(f"projects/{project_id}", "resolve_project", exc)
            return {}
