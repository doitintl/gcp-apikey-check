"""Service Account key age and usage checks via IAM API and Cloud Monitoring."""

import logging
import time
from datetime import datetime, timezone

import google.auth
import googleapiclient.discovery
from google.cloud import monitoring_v3
from google.api_core import exceptions as gcp_exceptions

from models import Finding, Severity

logger = logging.getLogger(__name__)

DOC_URL = "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"


def check_sa_keys(project_id: str, key_age_days: int, usage_days: int) -> list[Finding]:
    """Check all user-managed SA keys in a project for age and usage issues."""
    findings = []

    credentials, _ = google.auth.default()
    iam = googleapiclient.discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)

    # Fetch usage metrics once per project — maps key_id → last active date string
    key_last_used, monitoring_ok = _get_key_last_used(project_id, usage_days)

    # Paginate through all service accounts in the project
    service_accounts = _list_all_service_accounts(iam, project_id)

    for sa in service_accounts:
        sa_email = sa["email"]
        sa_name = sa["name"]

        try:
            keys_resp = (
                iam.projects()
                .serviceAccounts()
                .keys()
                .list(name=sa_name, keyTypes=["USER_MANAGED"])
                .execute()
            )
        except Exception as e:
            logger.warning(f"Cannot list keys for {sa_email}: {e}")
            continue

        user_keys = keys_resp.get("keys", [])
        if not user_keys:
            continue

        # Flag SAs that have accumulated too many keys
        if len(user_keys) > 2:
            findings.append(Finding(
                severity=Severity.MED,
                project_id=project_id,
                resource_name=sa_name,
                check_name="SA_EXCESSIVE_KEYS",
                description=(
                    f"Service account {sa_email} has {len(user_keys)} user-managed keys. "
                    "Each additional key widens the blast radius if any one is compromised."
                ),
                recommendation=(
                    "Reduce to at most one active key per service account. Delete all unused keys. "
                    "Prefer Workload Identity Federation to eliminate long-lived keys entirely."
                ),
                doc_url=DOC_URL,
                details={"sa_email": sa_email, "key_count": len(user_keys)},
            ))

        for key in user_keys:
            key_id = key["name"].split("/")[-1]
            created_at = _parse_time(key.get("validAfterTime"))
            age_days = (datetime.now(timezone.utc) - created_at).days if created_at else None
            last_used = key_last_used.get(key_id)

            # Age-based findings
            findings.extend(_age_findings(project_id, key["name"], sa_email, key_id, age_days, key_age_days))

            # No observed usage in the lookback window — only report if monitoring data was available.
            # If the fetch failed (permissions, API error), treat absence as unknown, not unused.
            if monitoring_ok and last_used is None:
                findings.append(Finding(
                    severity=Severity.MED,
                    project_id=project_id,
                    resource_name=key["name"],
                    check_name="SA_KEY_UNUSED",
                    description=(
                        f"SA key {key_id} ({sa_email}) has no observed usage in the last {usage_days} days."
                    ),
                    recommendation=(
                        "Verify whether this key is actually needed. "
                        "Disable it first, then delete after confirming no breakage. "
                        "Unused keys are dormant attack surface."
                    ),
                    doc_url=DOC_URL,
                    details={"sa_email": sa_email, "key_id": key_id, "lookback_days": usage_days},
                ))

            # INFO: last-used inventory record for every key (written to file, shown in console summary)
            findings.append(Finding(
                severity=Severity.INFO,
                project_id=project_id,
                resource_name=key["name"],
                check_name="SA_KEY_INVENTORY",
                description=f"SA key {key_id} for {sa_email}.",
                recommendation="Regularly audit this list and delete any keys that are no longer needed.",
                doc_url=DOC_URL,
                details={
                    "sa_email": sa_email,
                    "key_id": key_id,
                    "created": key.get("validAfterTime"),
                    "age_days": age_days,
                    "last_used": last_used or f"not seen in last {usage_days} days",
                    "expires": key.get("validBeforeTime"),
                },
            ))

    return findings


def _age_findings(
    project_id: str,
    key_name: str,
    sa_email: str,
    key_id: str,
    age_days: int | None,
    threshold: int,
) -> list[Finding]:
    if age_days is None or age_days <= threshold:
        return []

    # Key older than 2× threshold → CRITICAL, otherwise HIGH
    sev = Severity.CRITICAL if age_days > threshold * 2 else Severity.HIGH

    return [Finding(
        severity=sev,
        project_id=project_id,
        resource_name=key_name,
        check_name="SA_KEY_OLD",
        description=(
            f"SA key {key_id} ({sa_email}) is {age_days} days old "
            f"(policy threshold: {threshold} days)."
        ),
        recommendation=(
            f"Rotate this key immediately. Keys should be rotated every {threshold} days. "
            "Create a new key, update all consumers, then delete the old key. "
            "See: https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys#key-rotation"
        ),
        doc_url=DOC_URL,
        details={"sa_email": sa_email, "key_id": key_id, "age_days": age_days, "threshold_days": threshold},
    )]


def _get_key_last_used(project_id: str, usage_days: int) -> tuple[dict[str, str], bool]:
    """Query Cloud Monitoring for the most recent authentication event per SA key.

    Returns ({key_id: 'YYYY-MM-DD'}, monitoring_ok).
    monitoring_ok is False when the fetch failed — callers must not treat missing
    keys as unused in that case.
    """
    key_last_used: dict[str, str] = {}

    try:
        client = monitoring_v3.MetricServiceClient()

        end_time = time.time()
        start_time = end_time - (usage_days * 86400)

        interval = monitoring_v3.TimeInterval(
            end_time={"seconds": int(end_time)},
            start_time={"seconds": int(start_time)},
        )
        # Aggregate into daily buckets so we can find the last active day
        aggregation = monitoring_v3.Aggregation(
            alignment_period={"seconds": 86400},
            per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            group_by_fields=["metric.labels.key_id"],
        )

        request = monitoring_v3.ListTimeSeriesRequest(
            name=f"projects/{project_id}",
            filter='metric.type="iam.googleapis.com/service_account/key/authn_events_count"',
            interval=interval,
            aggregation=aggregation,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        )

        for ts in client.list_time_series(request=request):
            key_id = ts.metric.labels.get("key_id", "")
            if not key_id:
                continue

            last_active: datetime | None = None
            for point in ts.points:
                val = point.value.int64_value or point.value.double_value
                if val > 0:
                    dt = datetime.fromtimestamp(
                        point.interval.end_time.timestamp(), tz=timezone.utc
                    )
                    if last_active is None or dt > last_active:
                        last_active = dt

            if last_active:
                key_last_used[key_id] = last_active.strftime("%Y-%m-%d")

        return key_last_used, True

    except gcp_exceptions.PermissionDenied:
        logger.warning(f"Permission denied reading monitoring metrics for {project_id}")
    except Exception as e:
        logger.warning(f"Could not fetch SA key usage metrics for {project_id}: {e}")

    return {}, False


def _list_all_service_accounts(iam, project_id: str) -> list[dict]:
    """List all service accounts in a project, handling pagination."""
    accounts = []
    try:
        request = iam.projects().serviceAccounts().list(name=f"projects/{project_id}")
        while request is not None:
            resp = request.execute()
            accounts.extend(resp.get("accounts", []))
            request = iam.projects().serviceAccounts().list_next(request, resp)
    except Exception as e:
        logger.warning(f"Cannot list service accounts for {project_id}: {e}")
    return accounts


def _parse_time(time_str: str | None) -> datetime | None:
    if not time_str:
        return None
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except ValueError:
        return None
