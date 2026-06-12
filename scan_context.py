"""Shared, reusable GCP clients for a single scan run.

Building a googleapiclient discovery client re-downloads the API discovery
document; doing it per project (as the old code did) meant tens of thousands of
redundant fetches on a large org. Here we build each client once and reuse it.

Thread-safety split:
  * google.cloud.* gRPC clients (asset, monitoring, resource manager) are
    thread-safe — built once and shared across worker threads.
  * googleapiclient discovery clients wrap a non-thread-safe httplib2.Http, so
    each worker thread gets its own lazily-built copy via thread-local storage.
"""

import threading

import google.auth
import googleapiclient.discovery
from google.cloud import asset_v1, monitoring_v3, resourcemanager_v3

from gcp_errors import SkipCollector


class ScanContext:
    """Holds the credentials, clients, and skip collector for one scan."""

    def __init__(self) -> None:
        self.credentials, _ = google.auth.default()

        # gRPC clients — thread-safe, shared.
        self.asset_client = asset_v1.AssetServiceClient(credentials=self.credentials)
        self.monitoring_client = monitoring_v3.MetricServiceClient(credentials=self.credentials)
        self.projects_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

        # Discovery clients — per-thread (httplib2 is not thread-safe).
        self._local = threading.local()
        # orgpolicy is only used once on the main thread, so a plain attribute is fine.
        self._orgpolicy = None

        # Aggregated record of everything that could not be scanned.
        self.skips = SkipCollector()

    def _build(self, api: str, version: str):
        return googleapiclient.discovery.build(
            api, version, credentials=self.credentials, cache_discovery=False
        )

    def iam(self):
        """Per-thread IAM v1 client."""
        client = getattr(self._local, "iam", None)
        if client is None:
            client = self._local.iam = self._build("iam", "v1")
        return client

    def crm(self):
        """Per-thread Cloud Resource Manager v3 client."""
        client = getattr(self._local, "crm", None)
        if client is None:
            client = self._local.crm = self._build("cloudresourcemanager", "v3")
        return client

    @property
    def orgpolicy(self):
        """Org Policy v2 client (used once, main thread)."""
        if self._orgpolicy is None:
            self._orgpolicy = self._build("orgpolicy", "v2")
        return self._orgpolicy
