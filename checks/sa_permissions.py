"""Check service account IAM role assignments for excessive permissions."""

import logging
import re

import google.auth
import googleapiclient.discovery
from google.api_core import exceptions as gcp_exceptions

from models import Finding, Severity

logger = logging.getLogger(__name__)

DOC_URL = "https://cloud.google.com/iam/docs/using-iam-securely#least_privilege"

# Roles that grant org/project-wide dangerous access
CRITICAL_ROLES = {
    "roles/owner",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.workloadIdentityPoolAdmin",
}

HIGH_ROLES = {
    "roles/editor",
    "roles/iam.serviceAccountTokenCreator",
}

PRIMITIVE_ROLES: set[str] = set()  # viewer removed — read-only, not an escalation risk

# GCP-managed service agents — these roles are assigned automatically by Google
# and cannot be changed by the customer. Suppress with --suppress-google-sas.
_GOOGLE_MANAGED_SA_RE = re.compile(
    r"(@cloudservices\.gserviceaccount\.com$"          # Google APIs service agent
    r"|@cloudbuild\.gserviceaccount\.com$"             # Cloud Build service agent
    r"|^service-\d+@.*\.iam\.gserviceaccount\.com$"   # GCP service agents (service-{num}@...)
    r")",
    re.IGNORECASE,
)


def _is_google_managed(sa_email: str) -> bool:
    return bool(_GOOGLE_MANAGED_SA_RE.search(sa_email))


def check_sa_permissions(project_id: str, suppress_google_sas: bool = False) -> list[Finding]:
    """Check the project IAM policy for service accounts with overly broad roles."""
    findings = []

    credentials, _ = google.auth.default()
    crm = googleapiclient.discovery.build(
        "cloudresourcemanager", "v3", credentials=credentials, cache_discovery=False
    )

    try:
        policy = (
            crm.projects()
            .getIamPolicy(resource=f"projects/{project_id}", body={})
            .execute()
        )
    except Exception as e:
        logger.warning(f"Cannot retrieve IAM policy for {project_id}: {e}")
        return findings

    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue

            sa_email = member.removeprefix("serviceAccount:")

            if suppress_google_sas and _is_google_managed(sa_email):
                continue

            if role in CRITICAL_ROLES:
                sev = Severity.CRITICAL
            elif role in HIGH_ROLES or "admin" in role.lower():
                sev = Severity.HIGH
            elif role in PRIMITIVE_ROLES:
                sev = Severity.MED
            else:
                continue

            findings.append(Finding(
                severity=sev,
                project_id=project_id,
                resource_name=f"projects/{project_id}/serviceAccounts/{sa_email}",
                check_name="SA_EXCESSIVE_PERMISSIONS",
                description=(
                    f"Service account {sa_email} has role {role} on project {project_id}. "
                    "This grants overly broad permissions and violates least privilege."
                ),
                recommendation=(
                    f'Replace "{role}" with a custom or more specific predefined role '
                    "that grants only the permissions this service account actually needs. "
                    "Use the IAM Recommender to identify excess permissions."
                ),
                doc_url=DOC_URL,
                details={"sa_email": sa_email, "role": role, "project_id": project_id},
            ))

    return findings
