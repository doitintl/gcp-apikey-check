"""Check service account IAM role assignments for excessive permissions."""

import logging
import re

from gcp_errors import with_retry
from models import Finding, Severity
from scan_context import ScanContext

logger = logging.getLogger(__name__)

DOC_URL = "https://cloud.google.com/iam/docs/using-iam-securely#least_privilege"

# Roles that grant org/project-wide dangerous access.
CRITICAL_ROLES = {
    "roles/owner",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.workloadIdentityPoolAdmin",
}

# Editor plus roles that enable privilege escalation (mint tokens, manage IAM,
# manage service accounts / keys, define roles). A SA holding these is high risk.
HIGH_ROLES = {
    "roles/editor",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.roleAdmin",
    "roles/iam.organizationRoleAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.folderIamAdmin",
}

# Any other "*.admin" / "*Admin" role is a broad service admin (e.g. storage.admin,
# compute.admin). Worth surfacing, but not in the same league as IAM escalation —
# so it lands at MED rather than being lumped into HIGH like the old substring match.
_GENERIC_ADMIN_RE = re.compile(r"(\.admin|Admin)$")

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


def _severity_for_role(role: str) -> Severity | None:
    if role in CRITICAL_ROLES:
        return Severity.CRITICAL
    if role in HIGH_ROLES:
        return Severity.HIGH
    if _GENERIC_ADMIN_RE.search(role):
        return Severity.MED
    return None


def check_sa_permissions(
    ctx: ScanContext, project_id: str, suppress_google_sas: bool = False
) -> list[Finding]:
    """Check the project IAM policy for service accounts with overly broad roles."""
    findings = []
    scope = f"projects/{project_id}"
    crm = ctx.crm()

    try:
        policy = with_retry(lambda: (
            crm.projects()
            .getIamPolicy(resource=f"projects/{project_id}", body={})
            .execute()
        ))
    except Exception as exc:  # noqa: BLE001
        ctx.skips.record(scope, "sa_permissions", exc)
        return findings

    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        sev = _severity_for_role(role)
        if sev is None:
            continue

        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue

            sa_email = member.removeprefix("serviceAccount:")
            if suppress_google_sas and _is_google_managed(sa_email):
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
