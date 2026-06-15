"""Detect projects with Gemini / Vertex AI APIs enabled.

Implemented as a single Cloud Asset Inventory query across the whole scope
(org or project) rather than per-project Service Usage calls. This is one API
call instead of two-per-project, and it avoids the Service Usage quota-project
trap: a per-project ``services.get`` is billed against the caller's quota
project, so if Service Usage isn't enabled there every call 403s with
SERVICE_DISABLED — which is exactly what used to make this check blind.
"""

import json
import logging

from gcp_errors import with_retry
from models import Finding, Severity
from scan_context import ScanContext

logger = logging.getLogger(__name__)

DOC_GEMINI = "https://cloud.google.com/vertex-ai/generative-ai/docs/security/security-controls"
DOC_VERTEX = "https://cloud.google.com/vertex-ai/docs/general/security-controls"

# Maps each AI API service name to display metadata + the correlation check name.
AI_APIS = {
    "generativelanguage.googleapis.com": {
        "display_name": "Gemini API",
        "check_name": "GEMINI_API_ENABLED",
        "doc_url": DOC_GEMINI,
    },
    "aiplatform.googleapis.com": {
        "display_name": "Vertex AI API",
        "check_name": "VERTEX_AI_API_ENABLED",
        "doc_url": DOC_VERTEX,
    },
}


def check_enabled_ai_apis(
    ctx: ScanContext, scope: str, num_to_id: dict[str, str] | None = None
) -> list[Finding]:
    """Report every project in scope with an AI API enabled (INFO findings).

    ``scope`` is an Asset Inventory parent (``organizations/N`` or ``projects/ID``).
    """
    findings: list[Finding] = []
    num_to_id = num_to_id or {}

    from google.cloud import asset_v1

    request = asset_v1.ListAssetsRequest(
        parent=scope,
        asset_types=["serviceusage.googleapis.com/Service"],
        content_type=asset_v1.ContentType.RESOURCE,
        page_size=500,
    )

    try:
        pages = with_retry(lambda: list(ctx.asset_client.list_assets(request=request)))
    except Exception as exc:  # noqa: BLE001
        ctx.skips.record(scope, "enabled_ai_apis", exc)
        return findings

    for asset in pages:
        api_name = asset.name.rsplit("/", 1)[-1]
        meta = AI_APIS.get(api_name)
        if not meta:
            continue
        if not asset.resource or not asset.resource.data:
            continue

        data = json.loads(type(asset).to_json(asset)).get("resource", {}).get("data", {})
        if data.get("state") != "ENABLED":
            continue

        project_num = _project_from_asset_name(asset.name)
        project_id = num_to_id.get(project_num, project_num)

        findings.append(Finding(
            severity=Severity.INFO,
            project_id=project_id,
            resource_name=f"projects/{project_id}/services/{api_name}",
            check_name=meta["check_name"],
            description=(
                f'{meta["display_name"]} ({api_name}) is enabled in project "{project_id}". '
                "Verify that access is intentional and properly controlled."
            ),
            recommendation=(
                "Review IAM bindings to confirm only authorized principals can call this API. "
                "Enable Data Access audit logs and set budget alerts to detect unexpected usage. "
                "If this API is no longer needed, disable it to reduce attack surface."
            ),
            doc_url=meta["doc_url"],
            details={
                "api_name": api_name,
                "api_display_name": meta["display_name"],
                "state": "ENABLED",
            },
        ))

    return findings


def _project_from_asset_name(asset_name: str) -> str:
    """Extract project number from //serviceusage.googleapis.com/projects/{num}/services/..."""
    parts = asset_name.split("/")
    try:
        return parts[parts.index("projects") + 1]
    except (ValueError, IndexError):
        return "unknown"
