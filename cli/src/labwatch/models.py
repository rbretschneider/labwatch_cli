"""Data models for labwatch check results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @property
    def icon(self) -> str:
        return {
            Severity.OK: "[green]\u2714[/green]",
            Severity.WARNING: "[yellow]\u26a0[/yellow]",
            Severity.CRITICAL: "[red]\u2718[/red]",
            Severity.UNKNOWN: "[dim]?[/dim]",
        }[self]


@dataclass
class CheckResult:
    name: str
    severity: Severity
    message: str
    details: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class CheckReport:
    hostname: str
    results: List[CheckResult] = field(default_factory=list)

    @property
    def worst_severity(self) -> Severity:
        priority = [Severity.CRITICAL, Severity.WARNING, Severity.UNKNOWN, Severity.OK]
        for sev in priority:
            if any(r.severity == sev for r in self.results):
                return sev
        return Severity.OK

    @property
    def has_failures(self) -> bool:
        return self.worst_severity in (Severity.WARNING, Severity.CRITICAL)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "worst_severity": self.worst_severity.value,
            "results": [r.to_dict() for r in self.results],
        }
