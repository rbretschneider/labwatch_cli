"""Orchestrates checks and notifications."""

from typing import List, Optional

from labwatch.checks import get_check_classes
from labwatch.models import CheckReport, Severity
from labwatch.notifications import get_notifiers

SEVERITY_ORDER = {
    Severity.OK: 0,
    Severity.UNKNOWN: 1,
    Severity.WARNING: 2,
    Severity.CRITICAL: 3,
}

SEVERITY_BY_NAME = {
    "ok": Severity.OK,
    "unknown": Severity.UNKNOWN,
    "warning": Severity.WARNING,
    "critical": Severity.CRITICAL,
}


class Runner:
    def __init__(self, config: dict, verbose: bool = False):
        self.config = config
        self.verbose = verbose

    def run(self, modules: Optional[List[str]] = None) -> CheckReport:
        """Run all enabled checks (or a subset) and return a report."""
        hostname = self.config.get("hostname", "unknown")
        report = CheckReport(hostname=hostname)
        check_classes = get_check_classes()

        for name, cls in check_classes.items():
            if modules and name not in modules:
                continue

            check_cfg = self.config.get("checks", {}).get(name, {})
            if not check_cfg.get("enabled", True):
                continue

            try:
                check = cls(self.config, verbose=self.verbose)
                results = check.run()
                report.results.extend(results)
            except Exception as e:
                from labwatch.models import CheckResult
                report.results.append(CheckResult(
                    name=name,
                    severity=Severity.UNKNOWN,
                    message=f"Check failed to run: {e}",
                ))

        return report

    def notify(self, report: CheckReport) -> None:
        """Send notifications for a report with failures."""
        notifiers = get_notifiers(self.config)
        if not notifiers:
            return

        # Determine min_severity threshold
        min_sev_name = (
            self.config.get("notifications", {})
            .get("min_severity", "warning")
            .lower()
        )
        min_sev = SEVERITY_BY_NAME.get(min_sev_name, Severity.WARNING)
        min_order = SEVERITY_ORDER[min_sev]

        # Filter results to those at or above min_severity
        filtered = [
            r for r in report.results
            if SEVERITY_ORDER.get(r.severity, 0) >= min_order
        ]

        if not filtered:
            return

        # Compute worst severity from filtered results
        worst = max(filtered, key=lambda r: SEVERITY_ORDER.get(r.severity, 0)).severity

        title = f"[{report.hostname}] {worst.value.upper()}"
        lines = []
        for r in filtered:
            lines.append(f"{r.severity.value.upper()}: {r.name} - {r.message}")

        message = "\n".join(lines) if lines else "Check report has issues."

        for notifier in notifiers:
            try:
                notifier.send(title, message, severity=worst.value)
            except Exception:
                pass  # Don't crash the run on notification failure
