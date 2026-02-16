"""Generic process monitoring via pgrep/tasklist."""

import platform
import subprocess
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("process")
class ProcessCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("process", {})
        names = cfg.get("names", [])

        if not names:
            return []

        results = []
        for name in names:
            if not name or not isinstance(name, str):
                continue
            results.append(self._check_process(name))
        return results

    def _check_process(self, name: str) -> CheckResult:
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {name}*"],
                    capture_output=True, text=True, timeout=10,
                )
                # tasklist returns 0 even when no match; check output
                running = name.lower() in result.stdout.lower()
            else:
                result = subprocess.run(
                    ["pgrep", "-x", name],
                    capture_output=True, text=True, timeout=10,
                )
                running = result.returncode == 0

            if running:
                return CheckResult(
                    name=f"process:{name}",
                    severity=Severity.OK,
                    message=f"Process '{name}' is running",
                )
            return CheckResult(
                name=f"process:{name}",
                severity=Severity.CRITICAL,
                message=f"Process '{name}' is not running",
            )
        except FileNotFoundError:
            return CheckResult(
                name=f"process:{name}",
                severity=Severity.UNKNOWN,
                message="pgrep/tasklist not available",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"process:{name}",
                severity=Severity.CRITICAL,
                message=f"Timeout checking process '{name}'",
            )
        except Exception as e:
            return CheckResult(
                name=f"process:{name}",
                severity=Severity.UNKNOWN,
                message=str(e),
            )
