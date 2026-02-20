"""Network interface monitoring (link state, IP address, TX bytes)."""

import subprocess
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("network")
class NetworkCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("network", {})
        interfaces = cfg.get("interfaces", [])

        if not interfaces:
            return []

        # Verify ip command is available
        if not self._ip_available():
            return [
                CheckResult(
                    name="network",
                    severity=Severity.UNKNOWN,
                    message="ip command not available",
                )
            ]

        results = []
        for entry in interfaces:
            name = entry.get("name", "")
            severity = entry.get("severity", "critical").lower()
            if not name:
                continue
            results.extend(self._check_interface(name, severity))
        return results

    def _ip_available(self) -> bool:
        try:
            subprocess.run(
                ["ip", "link"], capture_output=True, timeout=5,
            )
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def _check_interface(self, iface: str, severity: str) -> List[CheckResult]:
        fail_sev = Severity.WARNING if severity == "warning" else Severity.CRITICAL
        results = []

        # Sub-check 1: link state
        results.append(self._check_link(iface, fail_sev))

        # Sub-check 2: IPv4 address
        results.append(self._check_addr(iface, fail_sev))

        # Sub-check 3: TX bytes
        tx_result = self._check_tx(iface, fail_sev)
        if tx_result is not None:
            results.append(tx_result)

        return results

    def _check_link(self, iface: str, fail_sev: Severity) -> CheckResult:
        try:
            result = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return CheckResult(
                    name=f"network:{iface}:link",
                    severity=fail_sev,
                    message=f"Interface '{iface}' not found",
                )
            # Virtual/tunnel interfaces (tun0, wg0, etc.) report
            # "state UNKNOWN" because they lack physical carrier
            # detection — treat UNKNOWN the same as UP.
            if "state UP" in result.stdout or "state UNKNOWN" in result.stdout:
                return CheckResult(
                    name=f"network:{iface}:link",
                    severity=Severity.OK,
                    message="UP",
                )
            return CheckResult(
                name=f"network:{iface}:link",
                severity=fail_sev,
                message="DOWN",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"network:{iface}:link",
                severity=fail_sev,
                message="Timeout checking link state",
            )

    def _check_addr(self, iface: str, fail_sev: Severity) -> CheckResult:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("inet "):
                    # Extract IP: "inet 10.8.0.2/24 ..."
                    ip = stripped.split()[1].split("/")[0]
                    return CheckResult(
                        name=f"network:{iface}:addr",
                        severity=Severity.OK,
                        message=ip,
                    )
            return CheckResult(
                name=f"network:{iface}:addr",
                severity=fail_sev,
                message="No IP assigned",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"network:{iface}:addr",
                severity=fail_sev,
                message="Timeout checking address",
            )

    def _check_tx(self, iface: str, fail_sev: Severity) -> CheckResult | None:
        tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"
        try:
            with open(tx_path) as f:
                tx_bytes = int(f.read().strip())
        except (OSError, ValueError):
            # File not readable (e.g. not on Linux) — skip gracefully
            return None

        if tx_bytes > 0:
            return CheckResult(
                name=f"network:{iface}:tx",
                severity=Severity.OK,
                message=f"{tx_bytes} bytes transmitted",
            )
        return CheckResult(
            name=f"network:{iface}:tx",
            severity=fail_sev,
            message="0 bytes transmitted",
        )
