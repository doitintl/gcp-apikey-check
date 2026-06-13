"""API key security checks via Cloud Asset Inventory."""

import json
import logging
from typing import Any

from google.cloud import asset_v1
from google.api_core import exceptions as gcp_exceptions

from models import Finding, Severity

logger = logging.getLogger(__name__)

# Maps APIs — keys for these should have strict HTTP referrer or IP restrictions
MAPS_APIS = {
    "maps-backend.googleapis.com",
    "maps-android-backend.googleapis.com",
    "maps-ios-backend.googleapis.com",
    "maps-embed-backend.googleapis.com",
    "static-maps-backend.googleapis.com",
    "maps.googleapis.com",
    "places-backend.googleapis.com",
    "places.googleapis.com",
    "routes.googleapis.com",
    "directions-backend.googleapis.com",
    "distance-matrix-backend.googleapis.com",
    "elevation-backend.googleapis.com",
    "geocoding-backend.googleapis.com",
    "geolocation.googleapis.com",
    "streetviewpublish.googleapis.com",
    "roads.googleapis.com",
}

# AI APIs — should use service accounts, not API keys
AI_APIS = {
    "generativelanguage.googleapis.com",  # Gemini
    "aiplatform.googleapis.com",           # Vertex AI
}

# Firebase APIs — commonly embedded in frontend code
FIREBASE_APIS = {
    "firebase.googleapis.com",
    "identitytoolkit.googleapis.com",
    "firebasestorage.googleapis.com",
    "firebaseremoteconfig.googleapis.com",
    "fcm.googleapis.com",
}

DOC_API_KEYS = "https://cloud.google.com/docs/authentication/api-keys-best-practices"
DOC_MAPS = "https://developers.google.com/maps/api-security-best-practices"


def check_api_keys(scope: str, num_to_id: dict[str, str] | None = None) -> list[Finding]:
    """Scan all API keys in scope (org or project) for security issues.

    num_to_id maps numeric project numbers to human-readable project IDs so
    findings display 'my-project' instead of '306419495665'.
    """
    findings = []
    client = asset_v1.AssetServiceClient()
    num_to_id = num_to_id or {}

    try:
        request = asset_v1.ListAssetsRequest(
            parent=scope,
            asset_types=["apikeys.googleapis.com/Key"],
            content_type=asset_v1.ContentType.RESOURCE,
            page_size=500,
        )
        for asset in client.list_assets(request=request):
            if not asset.resource or not asset.resource.data:
                continue
            # proto-plus wraps Struct as MapComposite; serialize via JSON to get a plain dict
            asset_dict = json.loads(type(asset).to_json(asset))
            key_data = asset_dict.get("resource", {}).get("data", {})
            project_num = _project_from_asset_name(asset.name)
            # Show the slug (e.g. "johnd-test-01") if we can resolve it;
            # resource_name retains the original numeric path for traceability.
            project_id = num_to_id.get(project_num, project_num)
            findings.extend(_check_single_key(project_id, asset.name, key_data))

    except gcp_exceptions.PermissionDenied as e:
        logger.warning(f"Permission denied scanning API keys in {scope}: {e}")
    except gcp_exceptions.InvalidArgument as e:
        logger.warning(f"Invalid scope for API key scan ({scope}): {e}")

    return findings


def _project_from_asset_name(asset_name: str) -> str:
    """Extract project ID from an asset name like //apikeys.googleapis.com/projects/my-proj/..."""
    parts = asset_name.split("/")
    try:
        return parts[parts.index("projects") + 1]
    except (ValueError, IndexError):
        return "unknown"


def _check_single_key(
    project_id: str,
    asset_name: str,
    key_data: dict[str, Any],
) -> list[Finding]:
    # Soft-deleted keys still appear in Asset Inventory until purged — skip them
    if key_data.get("deleteTime"):
        return []

    findings = []

    restrictions = key_data.get("restrictions", {})
    display_name = key_data.get("displayName") or asset_name.split("/")[-1]
    resource_name = key_data.get("name", asset_name)

    api_targets = restrictions.get("apiTargets", [])
    api_services = {t.get("service", "") for t in api_targets}

    has_app_restriction = any(
        k in restrictions
        for k in ("browserKeyRestrictions", "serverKeyRestrictions",
                  "androidKeyRestrictions", "iosKeyRestrictions")
    )
    has_api_restriction = bool(api_targets)

    is_maps_key = bool(api_services & MAPS_APIS)
    is_ai_key = bool(api_services & AI_APIS)
    is_firebase_key = bool(api_services & FIREBASE_APIS)

    base_details = {
        "display_name": display_name,
        "api_services": sorted(api_services),
        "has_application_restriction": has_app_restriction,
        "has_api_restriction": has_api_restriction,
    }

    # No application restriction — any app/IP can use this key
    if not has_app_restriction:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_NO_APP_RESTRICTION",
            description=f'API key "{display_name}" has no application restrictions. It can be used from any IP or application.',
            recommendation=(
                "Add application restrictions: HTTP referrers for browser/web keys, "
                "IP addresses for server keys, or package name + SHA-1 for Android/iOS keys."
            ),
            doc_url=DOC_API_KEYS,
            details=base_details,
        ))
    else:
        # Restriction exists — check that it isn't trivially bypassed
        findings.extend(_check_app_restriction_quality(
            project_id, resource_name, display_name, restrictions, base_details
        ))

    # No API restriction — key can call any Google API
    if not has_api_restriction:
        findings.append(Finding(
            severity=Severity.HIGH,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_NO_API_RESTRICTION",
            description=f'API key "{display_name}" has no API restrictions. A compromised key can call any Google API.',
            recommendation=(
                "Restrict this key to only the specific APIs your application uses "
                "via the 'API restrictions' setting in the Google Cloud Console."
            ),
            doc_url=DOC_API_KEYS,
            details=base_details,
        ))

    # Maps + AI APIs on same key — critical: leaked Maps key funds AI usage
    if is_maps_key and is_ai_key:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_MAPS_AI_COMBINED",
            description=(
                f'API key "{display_name}" is scoped for both Maps and AI APIs '
                f"({sorted(api_services & AI_APIS)}). Maps keys are routinely leaked from "
                "frontend code, which would grant anyone free access to Gemini/Vertex AI."
            ),
            recommendation=(
                "Split immediately into two separate keys: one Maps key with strict "
                "HTTP referrer restrictions, and one AI key with IP restrictions that "
                "is never embedded in client-side code."
            ),
            doc_url=DOC_MAPS,
            details=base_details,
        ))

    # AI API keys — these should use service accounts instead.
    # Severity is MED when an app restriction (e.g. IP allowlist) is present,
    # because the key's blast radius is meaningfully reduced; HIGH otherwise.
    for ai_api in sorted(api_services & AI_APIS):
        if has_app_restriction:
            ai_sev = Severity.MED
            ai_desc = (
                f'API key "{display_name}" is scoped for {ai_api} '
                "and has an application restriction, which reduces exposure. "
                "AI API keys are still high-value targets — prefer a service account."
            )
        else:
            ai_sev = Severity.HIGH
            ai_desc = (
                f'API key "{display_name}" is scoped for {ai_api}. '
                "AI API keys are high-value targets that can generate significant charges if leaked."
            )
        findings.append(Finding(
            severity=ai_sev,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_AI_SCOPE",
            description=ai_desc,
            recommendation=(
                "Use a service account with Workload Identity Federation instead of an API key "
                "for Gemini/Vertex AI. If an API key is required, restrict it to a specific IP "
                "range and never embed it in client-side code. Monitor usage and set budget alerts."
            ),
            doc_url=DOC_API_KEYS,
            details={**base_details, "ai_api": ai_api},
        ))

    # Firebase keys — designed to be public, so only flag when missing app restrictions
    # or combined with AI APIs (the specific high-risk combination).
    # Properly restricted Firebase-only keys are expected and not a finding.
    # Both cases are CRITICAL: Firebase keys are routinely embedded in public frontend
    # assets, so either condition exposes the key to the entire internet.
    if is_firebase_key and (not has_app_restriction or is_ai_key):
        findings.append(Finding(
            severity=Severity.CRITICAL,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_FIREBASE_SCOPE",
            description=(
                f'API key "{display_name}" is scoped for Firebase APIs'
                + (" and AI APIs — Firebase keys are routinely embedded in public frontend code, "
                   "which exposes your AI API access to anyone who inspects the page." if is_ai_key
                   else " without application restrictions. Firebase keys are routinely embedded "
                        "in public frontend code, making an unrestricted key fully public.")
            ),
            recommendation=(
                "Ensure this key has HTTP referrer or Android/iOS app restrictions. "
                "Verify it is NOT also scoped for Maps or AI APIs. "
                "Use Firebase Security Rules to protect data — do not rely on key secrecy."
            ),
            doc_url=DOC_MAPS,
            details=base_details,
        ))

    # Maps key checks — always fire a general finding, then add sub-checks on top
    if is_maps_key:
        maps_apis_present = sorted(api_services & MAPS_APIS)
        if not has_app_restriction:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                project_id=project_id,
                resource_name=resource_name,
                check_name="MAPS_KEY_NO_RESTRICTION",
                description=(
                    f'Maps API key "{display_name}" has no application restrictions '
                    f"and is scoped for: {maps_apis_present}. Maps keys are routinely "
                    "scraped from frontend code and mobile apps."
                ),
                recommendation=(
                    "Add the appropriate restriction for how this key is used: "
                    "HTTP referrers for web/JavaScript, Android app restriction (package + SHA-1) "
                    "for Android, iOS bundle ID for iOS, or IP address for server-side use. "
                    "Never use a single unrestricted key across multiple platforms."
                ),
                doc_url=DOC_MAPS,
                details={**base_details, "maps_apis": maps_apis_present},
            ))
        else:
            findings.append(Finding(
                severity=Severity.MED,
                project_id=project_id,
                resource_name=resource_name,
                check_name="MAPS_KEY_DETECTED",
                description=(
                    f'API key "{display_name}" is scoped for Maps APIs: {maps_apis_present}. '
                    "Verify restrictions are correctly configured for its deployment platform."
                ),
                recommendation=(
                    "Confirm the application restriction matches the platform: "
                    "HTTP referrers for web, Android/iOS restrictions for mobile. "
                    "Review the Maps API security best practices for your platform."
                ),
                doc_url=DOC_MAPS,
                details={**base_details, "maps_apis": maps_apis_present},
            ))
    # Too many APIs on one key — severity by count
    if has_api_restriction:
        n = len(api_services)
        if 4 <= n <= 6:
            sev = Severity.MED
        elif 7 <= n <= 9:
            sev = Severity.HIGH
        elif n >= 10:
            sev = Severity.CRITICAL
        else:
            sev = None

        if sev:
            findings.append(Finding(
                severity=sev,
                project_id=project_id,
                resource_name=resource_name,
                check_name="API_KEY_EXCESSIVE_SCOPE",
                description=(
                    f'API key "{display_name}" is scoped for {n} APIs. '
                    "A single compromised key exposes all of them."
                ),
                recommendation=(
                    "Create separate API keys per application following the principle of least privilege. "
                    "Each key should be restricted to only the APIs that specific application needs."
                ),
                doc_url=DOC_API_KEYS,
                details={**base_details, "api_count": n},
            ))

    return findings


def _is_risky_referrer(r: str) -> bool:
    """Return True if an HTTP referrer pattern provides no meaningful restriction.

    Path wildcards like https://example.com/* are valid GCP patterns and are safe.
    Domain-level wildcards (*, *.com, https://*.anything) are not.
    """
    if "localhost" in r or "127.0.0.1" in r or r.startswith("file://"):
        return True
    if "*" not in r:
        return False
    # Isolate the host portion — everything before the first path separator
    after_scheme = r.split("://", 1)[-1]  # strips scheme if present, else no-op
    host = after_scheme.split("/")[0]
    return "*" in host


def _check_app_restriction_quality(
    project_id: str,
    resource_name: str,
    display_name: str,
    restrictions: dict,
    base_details: dict,
) -> list[Finding]:
    """Validate that an application restriction is actually effective.

    Applies to all key types — not just Maps keys.
    """
    findings = []

    browser = restrictions.get("browserKeyRestrictions", {})
    server = restrictions.get("serverKeyRestrictions", {})
    android = restrictions.get("androidKeyRestrictions", {})
    ios = restrictions.get("iosKeyRestrictions", {})

    # Browser: wildcards in the domain portion and localhost bypass the restriction entirely.
    # Path-only wildcards like https://example.com/* are valid and must not be flagged.
    allowed_referrers = browser.get("allowedReferrers", [])
    risky = [r for r in allowed_referrers if _is_risky_referrer(r)]
    if risky:
        findings.append(Finding(
            severity=Severity.HIGH,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_BROAD_REFERRER",
            description=(
                f'API key "{display_name}" has HTTP referrer restrictions that are effectively '
                f"open: {risky}. Wildcards and localhost entries bypass the restriction."
            ),
            recommendation=(
                "Use specific full URL patterns (e.g., https://yourdomain.com/*). "
                "Remove localhost, 127.0.0.1, and file:// entries — "
                "use a separate key with no restrictions for local development only."
            ),
            doc_url=DOC_API_KEYS,
            details={**base_details, "risky_referrers": risky},
        ))

    # Server: 0.0.0.0/0 or ::/0 allows all IPs — no effective restriction
    allowed_ips = server.get("allowedIps", [])
    unrestricted_ips = [ip for ip in allowed_ips if ip in ("0.0.0.0/0", "::/0")]
    if unrestricted_ips:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_UNRESTRICTED_SERVER_IP",
            description=(
                f'API key "{display_name}" has a server IP restriction set to {unrestricted_ips}, '
                "which allows all IP addresses and provides no actual protection."
            ),
            recommendation=(
                "Replace 0.0.0.0/0 and ::/0 with the specific IP addresses or CIDR ranges "
                "of your servers. If the server IP is dynamic, use a NAT gateway with a fixed egress IP."
            ),
            doc_url=DOC_API_KEYS,
            details={**base_details, "unrestricted_ips": unrestricted_ips},
        ))

    # Android: package name without SHA-1 fingerprint — any APK can spoof the package name
    if android:
        apps = android.get("allowedApplications", [])
        missing_sha1 = [
            app.get("packageName", "unknown")
            for app in apps
            if not app.get("sha1Fingerprint")
        ]
        if missing_sha1:
            findings.append(Finding(
                severity=Severity.HIGH,
                project_id=project_id,
                resource_name=resource_name,
                check_name="API_KEY_ANDROID_NO_SHA1",
                description=(
                    f'API key "{display_name}" has Android restrictions with package name(s) '
                    f"but no SHA-1 fingerprint: {missing_sha1}. Any APK can claim these package names."
                ),
                recommendation=(
                    "Add the SHA-1 signing certificate fingerprint for every Android app restriction. "
                    "Without SHA-1, the package name restriction provides no real protection."
                ),
                doc_url=DOC_API_KEYS,
                details={**base_details, "packages_without_sha1": missing_sha1},
            ))

    # iOS: restriction type set but bundle ID list is empty — allows any iOS app
    if ios and not ios.get("allowedBundleIds"):
        findings.append(Finding(
            severity=Severity.HIGH,
            project_id=project_id,
            resource_name=resource_name,
            check_name="API_KEY_IOS_EMPTY_BUNDLE",
            description=(
                f'API key "{display_name}" has an iOS restriction configured but no bundle IDs listed. '
                "An empty bundle ID list may allow any iOS app to use this key."
            ),
            recommendation=(
                "Add the specific iOS bundle identifiers (e.g., com.yourcompany.yourapp) "
                "for every app that should be allowed to use this key."
            ),
            doc_url=DOC_API_KEYS,
            details=base_details,
        ))

    return findings
