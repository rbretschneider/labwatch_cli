"""Orchestrates checks and notifications."""

import logging
import sys
from typing import Dict, List, Optional

from labwatch.checks import get_check_classes
from labwatch.models import CheckReport, CheckResult, Severity
from labwatch.notifications import get_notifiers
from labwatch.state import load_state, save_state

_log = logging.getLogger("labwatch")

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
                report.results.append(CheckResult(
                    name=name,
                    severity=Severity.UNKNOWN,
                    message=f"Check failed to run: {e}",
                ))

        return report

    def notify(self, report: CheckReport) -> None:
        """Send notifications with deduplication and recovery alerts.

        - New failures are reported immediately.
        - Repeated identical failures are suppressed (no re-alert).
        - When a previously failing check returns to OK, a recovery
          notification is sent.
        """
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

        # Build current state: {check_name: severity_string}
        current: Dict[str, str] = {}
        for r in report.results:
            current[r.name] = r.severity.value

        # Load previous state
        prev_state = load_state()
        prev: Dict[str, str] = prev_state.get("checks", {})

        # Determine what changed
        new_failures: List[CheckResult] = []
        recoveries: List[str] = []

        for r in report.results:
            order = SEVERITY_ORDER.get(r.severity, 0)
            prev_sev = prev.get(r.name)
            prev_order = SEVERITY_ORDER.get(
                SEVERITY_BY_NAME.get(prev_sev, Severity.OK), 0
            ) if prev_sev else 0

            if order >= min_order:
                # This is a failure — only notify if it's new or changed
                if prev_sev != r.severity.value:
                    new_failures.append(r)
            elif r.severity == Severity.OK and prev_order >= min_order:
                # Was failing at/above threshold, now OK — recovery
                recoveries.append(r.name)

        # Also detect checks that disappeared (removed from config but
        # were previously failing) — don't alert for those.

        # Send failure notification for new/changed failures
        if new_failures:
            worst = max(new_failures, key=lambda r: SEVERITY_ORDER.get(r.severity, 0)).severity
            title = f"[{report.hostname}] {worst.value.upper()}"
            lines = [
                f"{r.severity.value.upper()}: {r.name} - {r.message}"
                for r in new_failures
            ]
            self._send(notifiers, title, "\n".join(lines), worst.value)
            _log.info("notified: %s", "; ".join(
                f"{r.name} {r.severity.value}" for r in new_failures))

        # Send recovery notification
        if recoveries:
            title = f"[{report.hostname}] RECOVERED"
            lines = [f"OK: {name} - recovered" for name in recoveries]
            self._send(notifiers, title, "\n".join(lines), "ok")
            _log.info("notified: recovered %s", ", ".join(recoveries))

        if not new_failures and not recoveries:
            _log.info("notify skipped: no state change (dedup)")

        # Persist current state
        prev_state["checks"] = current
        try:
            save_state(prev_state)
        except OSError as e:
            print(f"labwatch: failed to save state: {e}", file=sys.stderr)

    @staticmethod
    def _send(notifiers, title: str, message: str, severity: str) -> None:
        """Send a notification through all notifiers."""
        for notifier in notifiers:
            try:
                notifier.send(title, message, severity=severity)
            except Exception as e:
                print(
                    f"labwatch: notification via {notifier.name} failed: {e}",
                    file=sys.stderr,
                )
