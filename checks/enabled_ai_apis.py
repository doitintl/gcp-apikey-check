"""Checks whether Gemini API or Vertex AI API are enabled in a project."""

import logging

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from models import Finding, Severity

logger = logging.getLogger(__name__)

DOC_GEMINI = "https://cloud.google.com/vertex-ai/generative-ai/docs/security/security-controls"
DOC_VERTEX = "https://cloud.google.com/vertex-ai/docs/general/security-controls"

# Maps each AI API service name to display metadata
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


def check_enabled_ai_apis(project_id: str) -> list[Finding]:
    """Report Gemini API and Vertex AI API if either is enabled in the project.

    Uses the Service Usage API to check the enabled state of each AI service.
    Findings are INFO severity — purely informational so teams can audit which
    projects are running AI workloads and verify IAM / budget controls are in place.
    """
    findings = []
    service = build("serviceusage", "v1", cache_discovery=False)

    for api_name, meta in AI_APIS.items():
        resource_name = f"projects/{project_id}/services/{api_name}"
        try:
            response = service.services().get(name=resource_name).execute()
            state = response.get("state", "UNKNOWN")

            if state == "ENABLED":
                findings.append(Finding(
                    severity=Severity.INFO,
                    project_id=project_id,
                    resource_name=resource_name,
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
                        "state": state,
                    },
                ))
                logger.info(f"{meta['display_name']} is ENABLED in {project_id}")
            else:
                logger.debug(f"{meta['display_name']} is {state} in {project_id}")

        except HttpError as e:
            if e.resp.status == 403:
                logger.warning(f"Permission denied checking {api_name} in {project_id}: {e}")
            elif e.resp.status == 404:
                # 404 means the service has never been enabled in this project
                logger.debug(f"{api_name} not found in {project_id} (never enabled)")
            else:
                logger.warning(f"Unexpected error checking {api_name} in {project_id}: {e}")

    return findings
