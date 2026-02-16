"""Network connectivity checks via ping."""

import platform
import re
import subprocess
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("ping")
class PingCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        ping_cfg = self.config.get("checks", {}).get("ping", {})
        hosts = ping_cfg.get("hosts", [])
        timeout = ping_cfg.get("timeout", 5)

        if not hosts:
            return []

        results = []
        for host in hosts:
            results.append(self._ping_host(host, timeout))
        return results

    def _ping_host(self, host: str, timeout: int) -> CheckResult:
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 5,
            )

            if result.returncode == 0:
                rtt = self._parse_rtt(result.stdout)
                msg = f"Reachable ({rtt}ms)" if rtt else "Reachable"
                return CheckResult(
                    name=f"ping:{host}",
                    severity=Severity.OK,
                    message=msg,
                )
            return CheckResult(
                name=f"ping:{host}",
                severity=Severity.CRITICAL,
                message="Host unreachable",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"ping:{host}",
                severity=Severity.CRITICAL,
                message=f"Timeout after {timeout}s",
            )
        except Exception as e:
            return CheckResult(
                name=f"ping:{host}",
                severity=Severity.UNKNOWN,
                message=str(e),
            )

    @staticmethod
    def _parse_rtt(output: str) -> str:
        """Extract average round-trip time from ping output."""
        # Linux: rtt min/avg/max/mdev = 1.234/5.678/9.012/1.234 ms
        match = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", output)
        if match:
            return match.group(1)
        # Windows: Average = 5ms
        match = re.search(r"Average = (\d+)ms", output)
        if match:
            return match.group(1)
        # Windows: time=5ms or time<1ms
        match = re.search(r"time[<=](\d+)ms", output)
        if match:
            return match.group(1)
        return ""
