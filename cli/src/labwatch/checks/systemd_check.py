"""Generic systemd unit monitoring."""

import os
import subprocess
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity

_is_root = hasattr(os, "geteuid") and os.geteuid() == 0


@register("systemd")
class SystemdCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("systemd", {})
        units = cfg.get("units", [])

        if not units:
            return []

        results = []
        for entry in units:
            if isinstance(entry, str):
                name = entry
                severity = "critical"
            else:
                name = entry.get("name", "")
                severity = entry.get("severity", "critical").lower()
            if not name:
                continue
            results.append(self._check_unit(name, severity))
        return results

    @staticmethod
    def _query_active(unit: str) -> str:
        """Return the is-active status string for *unit*.

        Tries plain ``systemctl`` first.  If the unit is not reported as
        ``active`` and we are not root, retries with ``sudo -n`` so that
        units only visible to root (e.g. ``wg-quick@wg0``) are still
        detected.
        """
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=10,
        )
        status = result.stdout.strip()
        if status == "active" or _is_root:
            return status

        # Non-root fallback: try sudo -n (silent, no password prompt).
        try:
            sudo_result = subprocess.run(
                ["sudo", "-n", "systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=10,
            )
            sudo_status = sudo_result.stdout.strip()
            if sudo_status == "active":
                return sudo_status
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return status

    def _check_unit(self, unit: str, severity: str) -> CheckResult:
        fail_severity = Severity.WARNING if severity == "warning" else Severity.CRITICAL
        try:
            status = self._query_active(unit)
            if status == "active":
                return CheckResult(
                    name=f"systemd:{unit}",
                    severity=Severity.OK,
                    message=f"Unit '{unit}' is active",
                )
            return CheckResult(
                name=f"systemd:{unit}",
                severity=fail_severity,
                message=f"Unit '{unit}' is {status or 'inactive'}",
            )
        except FileNotFoundError:
            return CheckResult(
                name=f"systemd:{unit}",
                severity=Severity.UNKNOWN,
                message="systemctl not available",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"systemd:{unit}",
                severity=fail_severity,
                message=f"Timeout checking unit '{unit}'",
            )
        except Exception as e:
            return CheckResult(
                name=f"systemd:{unit}",
                severity=Severity.UNKNOWN,
                message=str(e),
            )
