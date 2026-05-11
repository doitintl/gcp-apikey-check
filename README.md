# gcp-apikey-check

A CLI tool that scans a Google Cloud organization or project for API key and service account security risks based on GCP best practices.

Ideally DO NOT USE API KEYS NOR SERVICE ACCOUNT KEYS WHENEVER POSSIBLE.  

See Google Docs:
- https://docs.cloud.google.com/docs/authentication/api-keys-best-practices
- https://developers.google.com/maps/api-security-best-practices
- https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys

---

> **This software is provided as-is, with no warranties of any kind and no support.** See the [MIT License](#license) below.

---

## What it checks

**API Keys** (via Cloud Asset Inventory)
- `API_KEY_NO_APP_RESTRICTION` — key has no application restriction (any IP/app can use it) [CRITICAL]
- `API_KEY_NO_API_RESTRICTION` — key is unrestricted and can call any Google API [HIGH]
- `API_KEY_BROAD_REFERRER` — HTTP referrer restriction uses wildcards or localhost [HIGH]
- `API_KEY_UNRESTRICTED_SERVER_IP` — server IP restriction set to `0.0.0.0/0` or `::/0` [CRITICAL]
- `API_KEY_ANDROID_NO_SHA1` — Android restriction missing SHA-1 fingerprint [HIGH]
- `API_KEY_IOS_EMPTY_BUNDLE` — iOS restriction has no bundle IDs listed [HIGH]
- `API_KEY_MAPS_AI_COMBINED` — Maps and AI APIs on the same key [CRITICAL]
- `API_KEY_AI_SCOPE` — key scoped for Gemini / Vertex AI [HIGH]
- `API_KEY_FIREBASE_SCOPE` — key scoped for Firebase APIs without proper restrictions [HIGH]
- `MAPS_KEY_NO_RESTRICTION` — Maps key with no application restriction [CRITICAL]
- `MAPS_KEY_DETECTED` — Maps key present; prompts review of platform restrictions [MED]
- `API_KEY_EXCESSIVE_SCOPE` — key scoped for 4+ APIs [MED–CRITICAL]

**Service Account Keys** (per project, via IAM API + Cloud Monitoring)
- `SA_KEY_OLD` — key exceeds age threshold (HIGH) or 2× threshold (CRITICAL)
- `SA_KEY_UNUSED` — no authentication events in the lookback window [MED]
- `SA_EXCESSIVE_KEYS` — service account has more than 2 user-managed keys [MED]
- `SA_KEY_INVENTORY` — informational inventory of all user-managed keys [INFO]

**Service Account Permissions** (per project, via IAM policy)
- `SA_EXCESSIVE_PERMISSIONS` — service account holds `owner`, `editor`, `iam.securityAdmin`, or other high-privilege roles [CRITICAL/HIGH]

**Organization Policies** (org-level scans only)
- `ORG_SA_KEY_CREATION_ALLOWED` — `iam.disableServiceAccountKeyCreation` not enforced [HIGH]
- `ORG_SA_KEY_UPLOAD_ALLOWED` — `iam.disableServiceAccountKeyUpload` not enforced [MED]

---

## Install

Requires Python 3.12+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone https://github.com/doitintl/gcp-apikey-check
cd gcp-apikey-check
uv sync
```

Authenticate with GCP:

```bash
gcloud auth application-default login
```

The identity used must have at minimum:
- `roles/cloudasset.viewer` (org or project level)
- `roles/iam.securityReviewer` (per project)
- `roles/monitoring.viewer` (per project)
- `roles/orgpolicy.policyViewer` (org level, for org scans)

---

## Run

```bash
# Scan an entire organization
uv run gcpkeyscan.py --org-id 123456789

# Scan a single project
uv run gcpkeyscan.py --project-id my-project-id

# Save results to a specific directory, JSON only
uv run gcpkeyscan.py --org-id 123456789 --output json --output-dir ./reports
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--org-id ORG_ID` | — | GCP organization ID to scan *(mutually exclusive with `--project-id`)* |
| `--project-id PROJECT_ID` | — | GCP project ID to scan *(mutually exclusive with `--org-id`)* |
| `--key-age-days DAYS` | `90` | Flag SA keys older than this. Keys older than 2× this threshold are CRITICAL. |
| `--usage-days DAYS` | `30` | Lookback window for SA key usage metrics |
| `--output {json,csv,both}` | `both` | Output file format |
| `--output-dir DIR` | `.` | Directory for output files |
| `--include-google-sas` | off | Include Google-managed service agents in permission findings (noisy; not actionable) |
| `--all-sa-permissions` | off | Check permissions for all SAs, not just those with user-managed keys |
| `--verbose / -v` | off | Show API call details and warnings |

Output files are written as `gcp-security-scan-<timestamp>.json` / `.csv`.

---

## License

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**
