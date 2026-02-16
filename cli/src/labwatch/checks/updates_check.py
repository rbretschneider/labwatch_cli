"""System package update checks (apt, dnf, yum)."""

import subprocess
from typing import List, Optional

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("updates")
class UpdatesCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("updates", {})

        for method in (self._check_apt, self._check_dnf, self._check_yum):
            result = method(cfg)
            if result is not None:
                return [result]

        return [CheckResult(
            name="updates",
            severity=Severity.UNKNOWN,
            message="No supported package manager found (apt, dnf, yum)",
        )]

    def _check_apt(self, cfg: dict) -> Optional[CheckResult]:
        try:
            proc = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return CheckResult(
                name="updates",
                severity=Severity.UNKNOWN,
                message="apt timed out",
            )

        # Output: first line is "Listing..." header, then "pkg/suite version ..."
        lines = [l for l in proc.stdout.strip().splitlines() if "/" in l]
        return self._make_result(len(lines), cfg, self._package_list(lines))

    def _check_dnf(self, cfg: dict) -> Optional[CheckResult]:
        try:
            proc = subprocess.run(
                ["dnf", "check-update", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return CheckResult(
                name="updates",
                severity=Severity.UNKNOWN,
                message="dnf timed out",
            )

        # dnf returns exit 100 when updates available, 0 when none
        if proc.returncode == 0:
            return self._make_result(0, cfg)

        lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
        return self._make_result(len(lines), cfg, self._package_list(lines))

    def _check_yum(self, cfg: dict) -> Optional[CheckResult]:
        try:
            proc = subprocess.run(
                ["yum", "check-update", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return CheckResult(
                name="updates",
                severity=Severity.UNKNOWN,
                message="yum timed out",
            )

        if proc.returncode == 0:
            return self._make_result(0, cfg)

        lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
        return self._make_result(len(lines), cfg, self._package_list(lines))

    def _make_result(
        self, count: int, cfg: dict, details: Optional[str] = None,
    ) -> CheckResult:
        warn_threshold = cfg.get("warning_threshold", 1)
        crit_threshold = cfg.get("critical_threshold", 50)

        if count == 0:
            return CheckResult(
                name="updates",
                severity=Severity.OK,
                message="System is up to date",
            )

        if count >= crit_threshold:
            sev = Severity.CRITICAL
        elif count >= warn_threshold:
            sev = Severity.WARNING
        else:
            sev = Severity.OK

        label = "update" if count == 1 else "updates"
        return CheckResult(
            name="updates",
            severity=sev,
            message=f"{count} pending {label}",
            details=details if self.verbose else None,
        )

    @staticmethod
    def _package_list(lines: List[str]) -> str:
        """Extract package names from output lines for verbose details."""
        names = []
        for line in lines[:20]:
            name = line.split("/")[0] if "/" in line else line.split()[0] if line.split() else line
            names.append(name)
        suffix = f"\n  ... and {len(lines) - 20} more" if len(lines) > 20 else ""
        return "  " + "\n  ".join(names) + suffix
