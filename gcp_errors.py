"""Error classification, retry, and skip-tracking for resilient org-scale scans.

At organization scope a scan touches thousands of projects, and a large fraction
will legitimately deny access or have APIs disabled. Treating every such failure
as a scary warning (or worse, swallowing it into an empty result) is the core
reason this tool used to look "clean" when it had actually scanned nothing.

Instead we *classify* each failure into a small set of reasons, count them, and
surface a coverage summary at the end. Transient failures are retried.
"""

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass
from enum import Enum

from google.api_core import exceptions as gapi
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class SkipReason(str, Enum):
    PERMISSION_DENIED = "permission denied"
    API_DISABLED = "API disabled"
    NOT_FOUND = "not found"
    QUOTA = "quota / rate limited"
    TRANSIENT = "transient error"
    INVALID = "invalid argument"
    OTHER = "other error"


# Reasons worth retrying — the call may succeed if we back off and try again.
_RETRYABLE = {SkipReason.QUOTA, SkipReason.TRANSIENT}

# Substrings that mark a "service not enabled" 403 regardless of transport.
_DISABLED_MARKERS = ("SERVICE_DISABLED", "has not been used in project", "it is disabled")


def _http_status(exc: BaseException) -> int | None:
    resp = getattr(exc, "resp", None)
    if resp is not None:
        try:
            return int(resp.status)
        except (TypeError, ValueError):
            pass
    return getattr(exc, "status_code", None)


def classify_error(exc: BaseException) -> SkipReason:
    """Map any GCP client exception to a coarse, user-meaningful reason."""
    # gRPC / google-api-core exceptions (google.cloud.* clients)
    if isinstance(exc, gapi.PermissionDenied):
        return SkipReason.API_DISABLED if _has_disabled_marker(exc) else SkipReason.PERMISSION_DENIED
    if isinstance(exc, gapi.NotFound):
        return SkipReason.NOT_FOUND
    if isinstance(exc, gapi.ResourceExhausted):
        return SkipReason.QUOTA
    if isinstance(exc, (gapi.ServiceUnavailable, gapi.DeadlineExceeded, gapi.InternalServerError)):
        return SkipReason.TRANSIENT
    if isinstance(exc, gapi.InvalidArgument):
        return SkipReason.INVALID

    # HttpError (googleapiclient discovery clients)
    if isinstance(exc, HttpError):
        status = _http_status(exc)
        if status == 403:
            return SkipReason.API_DISABLED if _has_disabled_marker(exc) else SkipReason.PERMISSION_DENIED
        if status == 404:
            return SkipReason.NOT_FOUND
        if status == 429:
            return SkipReason.QUOTA
        if status in (500, 503, 504):
            return SkipReason.TRANSIENT
        if status == 400:
            return SkipReason.INVALID

    if _has_disabled_marker(exc):
        return SkipReason.API_DISABLED
    return SkipReason.OTHER


def _has_disabled_marker(exc: BaseException) -> bool:
    text = str(exc)
    return any(marker in text for marker in _DISABLED_MARKERS)


def with_retry(fn, *, tries: int = 3, base_delay: float = 0.5, max_delay: float = 8.0, _sleep=time.sleep):
    """Call ``fn`` with exponential backoff on quota / transient failures.

    Non-retryable errors (permission denied, API disabled, …) raise immediately so
    the caller can record them as a skip without wasting time on doomed retries.
    """
    last_exc: BaseException | None = None
    for attempt in range(tries):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — classify then re-raise
            if classify_error(exc) not in _RETRYABLE or attempt == tries - 1:
                raise
            last_exc = exc
            delay = min(max_delay, base_delay * (2 ** attempt))
            logger.debug("transient failure, retrying in %.1fs (%d/%d): %s", delay, attempt + 1, tries, exc)
            _sleep(delay)
    assert last_exc is not None
    raise last_exc


@dataclass(frozen=True)
class Skip:
    """A check that could not be completed for a given scope."""
    scope: str
    check: str
    reason: SkipReason
    detail: str = ""


class SkipCollector:
    """Thread-safe collector for checks skipped during a (possibly concurrent) scan."""

    def __init__(self) -> None:
        self._skips: list[Skip] = []
        self._lock = threading.Lock()

    def record(self, scope: str, check: str, exc: BaseException) -> SkipReason:
        reason = classify_error(exc)
        detail = str(exc).strip().split("\n", 1)[0][:200]
        with self._lock:
            self._skips.append(Skip(scope=scope, check=check, reason=reason, detail=detail))
        logger.debug("skip [%s] %s: %s — %s", check, scope, reason.value, detail)
        return reason

    @property
    def skips(self) -> list[Skip]:
        with self._lock:
            return list(self._skips)

    def is_empty(self) -> bool:
        with self._lock:
            return not self._skips

    def by_reason(self) -> Counter:
        return Counter(s.reason for s in self.skips)

    def example_scopes(self, reason: SkipReason, limit: int = 3) -> list[str]:
        seen: list[str] = []
        for s in self.skips:
            if s.reason is reason and s.scope not in seen:
                seen.append(s.scope)
                if len(seen) >= limit:
                    break
        return seen
