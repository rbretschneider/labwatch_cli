"""System resource checks: disk, memory, CPU load."""

from typing import List

import psutil

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("system")
class SystemCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        results = []
        thresholds = self.config.get("checks", {}).get("system", {}).get("thresholds", {})

        results.extend(self._check_disk(thresholds))
        results.extend(self._check_memory(thresholds))
        results.extend(self._check_cpu(thresholds))

        return results

    def _check_disk(self, thresholds: dict) -> List[CheckResult]:
        warn = thresholds.get("disk_warning", 80)
        crit = thresholds.get("disk_critical", 90)
        results = []

        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                except PermissionError:
                    continue

                pct = usage.percent
                name = f"disk:{part.mountpoint}"

                if pct >= crit:
                    sev = Severity.CRITICAL
                elif pct >= warn:
                    sev = Severity.WARNING
                else:
                    sev = Severity.OK

                total_gb = usage.total / (1024 ** 3)
                free_gb = usage.free / (1024 ** 3)
                results.append(CheckResult(
                    name=name,
                    severity=sev,
                    message=f"{pct:.1f}% used ({free_gb:.1f}GB free of {total_gb:.1f}GB)",
                ))
        except Exception as e:
            results.append(CheckResult(
                name="disk",
                severity=Severity.UNKNOWN,
                message=f"Failed to check disk: {e}",
            ))

        return results

    def _check_memory(self, thresholds: dict) -> List[CheckResult]:
        warn = thresholds.get("memory_warning", 80)
        crit = thresholds.get("memory_critical", 90)

        try:
            mem = psutil.virtual_memory()
            pct = mem.percent

            if pct >= crit:
                sev = Severity.CRITICAL
            elif pct >= warn:
                sev = Severity.WARNING
            else:
                sev = Severity.OK

            total_gb = mem.total / (1024 ** 3)
            avail_gb = mem.available / (1024 ** 3)
            return [CheckResult(
                name="memory",
                severity=sev,
                message=f"{pct:.1f}% used ({avail_gb:.1f}GB available of {total_gb:.1f}GB)",
            )]
        except Exception as e:
            return [CheckResult(
                name="memory",
                severity=Severity.UNKNOWN,
                message=f"Failed to check memory: {e}",
            )]

    def _check_cpu(self, thresholds: dict) -> List[CheckResult]:
        warn = thresholds.get("cpu_warning", 80)
        crit = thresholds.get("cpu_critical", 95)

        try:
            cpu_count = psutil.cpu_count() or 1
            cpu_pct = psutil.cpu_percent(interval=1)

            if cpu_pct >= crit:
                sev = Severity.CRITICAL
            elif cpu_pct >= warn:
                sev = Severity.WARNING
            else:
                sev = Severity.OK

            return [CheckResult(
                name="cpu",
                severity=sev,
                message=f"{cpu_pct:.1f}% ({cpu_count} cores)",
            )]
        except Exception as e:
            return [CheckResult(
                name="cpu",
                severity=Severity.UNKNOWN,
                message=f"Failed to check CPU: {e}",
            )]
