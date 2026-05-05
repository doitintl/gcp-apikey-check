"""Check organization-level policies for SA key governance."""

import logging

import google.auth
import googleapiclient.discovery
from googleapiclient.errors import HttpError

from models import Finding, Severity

logger = logging.getLogger(__name__)

DOC_URL = "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys#disable-key-creation"

# Each entry: constraint_id → (severity, check_name, description, recommendation)
CONSTRAINTS = {
    "iam.disableServiceAccountKeyCreation": (
        Severity.HIGH,
        "ORG_SA_KEY_CREATION_ALLOWED",
        "Service account key creation is not disabled at the organization level. "
        "Developers in any project can create long-lived credentials without central oversight.",
        (
            "Enforce the `constraints/iam.disableServiceAccountKeyCreation` organization policy. "
            "Grant exceptions only to specific projects via the `allowedValues` field, "
            "with an approval workflow. Migrate workloads to Workload Identity Federation instead."
        ),
    ),
    "iam.disableServiceAccountKeyUpload": (
        Severity.MED,
        "ORG_SA_KEY_UPLOAD_ALLOWED",
        "Service account key upload is not disabled at the organization level. "
        "External or user-generated keys can be uploaded without oversight.",
        (
            "Enforce the `constraints/iam.disableServiceAccountKeyUpload` organization policy "
            "to prevent upload of keys that were generated outside of Google's infrastructure."
        ),
    ),
}


def check_org_policies(org_id: str) -> list[Finding]:
    """Check that key governance org policies are enforced."""
    findings = []

    credentials, _ = google.auth.default()
    orgpolicy = googleapiclient.discovery.build(
        "orgpolicy", "v2", credentials=credentials, cache_discovery=False
    )

    for constraint_id, (severity, check_name, description, recommendation) in CONSTRAINTS.items():
        policy_name = f"organizations/{org_id}/policies/{constraint_id}"
        enforced = _is_enforced(orgpolicy, policy_name)

        if enforced is False:
            findings.append(Finding(
                severity=severity,
                project_id=f"organizations/{org_id}",
                resource_name=f"organizations/{org_id}",
                check_name=check_name,
                description=description,
                recommendation=recommendation,
                doc_url=DOC_URL,
                details={"constraint": f"constraints/{constraint_id}", "org_id": org_id},
            ))

    return findings


def _is_enforced(orgpolicy, policy_name: str) -> bool | None:
    """Return True if enforced, False if not set (policy absent = not enforced), None if indeterminate.

    None means the check could not be completed (permission denied, transient error, etc.)
    and should not produce a finding.
    """
    try:
        policy = orgpolicy.organizations().policies().get(name=policy_name).execute()
        rules = policy.get("spec", {}).get("rules", [])
        return any(rule.get("enforce") is True for rule in rules)
    except HttpError as e:
        if e.resp.status == 404:
            # Policy not set at all → constraint is not enforced
            return False
        logger.warning(f"Could not check policy {policy_name}: HTTP {e.resp.status}")
        return None
    except Exception as e:
        logger.warning(f"Could not check policy {policy_name}: {e}")
        return None
