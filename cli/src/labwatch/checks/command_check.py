"""Generic command runner check — the universal escape hatch."""

import shlex
import subprocess
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity

_DEFAULT_TIMEOUT = 30


@register("command")
class CommandCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("command", {})
        commands = cfg.get("commands", [])

        if not commands:
            return []

        results = []
        for entry in commands:
            name = entry.get("name", "")
            command = entry.get("command", "")
            if not name or not command:
                continue

            # Schedule filtering: when module_filter is set, only run
            # entries whose schedule matches.  Entries without a schedule
            # field are skipped when any filter is active.
            if self.module_filter:
                entry_schedule = entry.get("schedule", "")
                if entry_schedule != self.module_filter:
                    continue

            results.append(self._run_command(entry))
        return results

    def _run_command(self, entry: dict) -> CheckResult:
        name = entry["name"]
        command = entry["command"]
        container = entry.get("container", "")
        timeout = entry.get("timeout", _DEFAULT_TIMEOUT)
        expect_exit = entry.get("expect_exit", 0)
        expect_output = entry.get("expect_output", "")
        severity = entry.get("severity", "critical").lower()
        fail_severity = Severity.WARNING if severity == "warning" else Severity.CRITICAL

        # Build the actual shell command
        if container:
            shell_cmd = f"docker exec {shlex.quote(container)} {command}"
        else:
            shell_cmd = command

        try:
            result = subprocess.run(
                shell_cmd, shell=True,
                capture_output=True, text=True, timeout=timeout,
            )

            combined = result.stdout + result.stderr

            # Check exit code
            if result.returncode != expect_exit:
                return CheckResult(
                    name=f"command:{name}",
                    severity=fail_severity,
                    message=f"Exit code {result.returncode} (expected {expect_exit})",
                    details=combined[:500] if self.verbose else None,
                )

            # Check output pattern
            if expect_output and expect_output not in combined:
                return CheckResult(
                    name=f"command:{name}",
                    severity=fail_severity,
                    message=f"Output missing expected string '{expect_output}'",
                    details=combined[:500] if self.verbose else None,
                )

            return CheckResult(
                name=f"command:{name}",
                severity=Severity.OK,
                message="OK",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"command:{name}",
                severity=fail_severity,
                message=f"Command timed out ({timeout}s)",
            )
        except Exception as e:
            return CheckResult(
                name=f"command:{name}",
                severity=Severity.UNKNOWN,
                message=str(e),
            )
