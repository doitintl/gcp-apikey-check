#!/usr/bin/env python3
"""GCP API Key and Service Account security scanner.

Scans a Google Cloud org or project for API keys and Service Account keys
that violate Google security best practices.

Authentication: uses Application Default Credentials (ADC).
Run `gcloud auth application-default login` before using this script,
or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file.
"""

import argparse
import logging

from scanner import Scanner
from report import Report


def main():
    parser = argparse.ArgumentParser(
        description="Scan GCP org or project for API key and Service Account security risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run gcpkeyscan.py --org-id 123456789
  uv run gcpkeyscan.py --project-id my-project --key-age-days 60 --output json
  uv run gcpkeyscan.py --org-id 123456789 --output csv --output-dir ./reports
        """,
    )

    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--org-id", metavar="ORG_ID", help="Google Cloud organization ID to scan")
    scope.add_argument("--project-id", metavar="PROJECT_ID", help="Google Cloud project ID to scan")

    parser.add_argument(
        "--key-age-days",
        type=int,
        default=90,
        metavar="DAYS",
        help="Flag SA keys older than this many days (default: 90). Keys older than 2x this are CRITICAL.",
    )
    parser.add_argument(
        "--usage-days",
        type=int,
        default=30,
        metavar="DAYS",
        help="Lookback window in days for SA key usage metrics (default: 30).",
    )
    parser.add_argument(
        "--output",
        choices=["json", "csv", "both"],
        default="both",
        help="Output file format (default: both).",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        metavar="DIR",
        help="Directory for output files (default: current directory).",
    )
    parser.add_argument(
        "--include-google-sas",
        action="store_true",
        help=(
            "Include SA permission findings for Google-managed service agents "
            "(e.g. *@cloudservices.gserviceaccount.com, service-{n}@*.iam.gserviceaccount.com). "
            "These roles are assigned by GCP automatically and cannot be changed by the customer. "
            "By default they are suppressed since they produce noise without actionable remediation."
        ),
    )
    parser.add_argument(
        "--all-sa-permissions",
        action="store_true",
        help=(
            "Check SA permissions for every service account in the project, not just those "
            "with user-managed keys. By default only SAs with keys are reported, since a "
            "keyless SA cannot be used with leaked credentials."
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent worker threads for per-project checks (default: 10).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (shows per-scope skip detail and retries).",
    )

    args = parser.parse_args()

    _configure_logging(args.verbose)

    scanner = Scanner(
        org_id=args.org_id,
        project_id=args.project_id,
        key_age_days=args.key_age_days,
        usage_days=args.usage_days,
        suppress_google_sas=not args.include_google_sas,
        all_sa_permissions=args.all_sa_permissions,
        max_workers=args.max_workers,
    )

    result = scanner.run()

    report = Report(result, output_dir=args.output_dir)
    report.print_console()
    report.save(args.output)


def _configure_logging(verbose: bool):
    """Quiet the noisy Google client libraries.

    At org scale a large fraction of projects legitimately 403, and the
    google-api-python-client transport logs every one of those at WARNING.
    That spew is what made the tool feel broken — failures are now classified
    and summarised in the coverage panel instead, so we silence the raw chatter.
    With -v, our own DEBUG skip/retry detail is shown, but the library transport
    stays quiet regardless.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("googleapiclient", "googleapiclient.http", "googleapiclient.discovery_cache",
                  "google.auth", "google.api_core", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.ERROR)


if __name__ == "__main__":
    main()
