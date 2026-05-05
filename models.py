"""Data models for security findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INFO = "INFO"


# Used for sorting — lower number = higher priority
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MED: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    severity: Severity
    project_id: str
    resource_name: str
    check_name: str
    description: str
    recommendation: str
    doc_url: str
    details: dict[str, Any] = field(default_factory=dict)

    def resource_label(self) -> str:
        """Human-readable resource identifier for CSV/JSON output."""
        if name := self.details.get("display_name"):
            return name
        if email := self.details.get("sa_email"):
            return email
        return self.resource_name.split("/")[-1] or self.resource_name

    def to_dict(self) -> dict:
        d = {
            "severity": self.severity.value,
            "project_id": self.project_id,
            "resource_name": self.resource_name,
            "resource_label": self.resource_label(),
            "check_name": self.check_name,
            "description": self.description,
            "recommendation": self.recommendation,
            "doc_url": self.doc_url,
        }
        d.update(self.details)
        return d
