"""Filesystem mount monitoring (mounted, reachable, optionally writable)."""

import re
import subprocess
import sys
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity

_TIMEOUT = 10  # seconds for stat / test -w subprocess calls

_OCTAL_ESC_RE = re.compile(r"\\([0-7]{3})")


def _decode_mount_path(raw: str) -> str:
    """Decode octal escapes in /proc/mounts paths (e.g. ``\\040`` -> space)."""
    return _OCTAL_ESC_RE.sub(lambda m: chr(int(m.group(1), 8)), raw)


@register("mounts")
class MountsCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        cfg = self.config.get("checks", {}).get("mounts", {})
        mounts = cfg.get("mounts", [])

        if not mounts:
            return []

        if sys.platform != "linux":
            return [
                CheckResult(
                    name="mounts",
                    severity=Severity.UNKNOWN,
                    message="/proc/mounts not available (non-Linux)",
                )
            ]

        mounted_paths = self._read_proc_mounts()

        results = []
        for entry in mounts:
            path = entry.get("path", "")
            if not path:
                continue
            severity = entry.get("severity", "critical").lower()
            writable = entry.get("writable", False)
            results.extend(
                self._check_mount(path, severity, writable, mounted_paths)
            )
        return results

    def _read_proc_mounts(self) -> set:
        """Parse /proc/mounts and return the set of mount points.

        /proc/mounts encodes special characters as octal escapes
        (e.g. spaces as ``\\040``), so we decode them before comparing.
        """
        try:
            with open("/proc/mounts") as f:
                mounts = set()
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        mounts.add(_decode_mount_path(parts[1]))
                return mounts
        except OSError:
            return set()

    def _check_mount(
        self,
        path: str,
        severity: str,
        writable: bool,
        mounted_paths: set,
    ) -> List[CheckResult]:
        fail_sev = Severity.WARNING if severity == "warning" else Severity.CRITICAL
        results = []

        # Sub-check 1: is it mounted?
        is_mounted = path in mounted_paths
        if is_mounted:
            results.append(CheckResult(
                name=f"mounts:{path}:mounted",
                severity=Severity.OK,
                message="mounted",
            ))
        else:
            results.append(CheckResult(
                name=f"mounts:{path}:mounted",
                severity=fail_sev,
                message="not mounted",
            ))
            # If not mounted, skip reachable/writable — they'd be misleading
            return results

        # Sub-check 2: is it reachable? (catches stale NFS)
        results.append(self._check_reachable(path, fail_sev))

        # Sub-check 3 (optional): is it writable?
        if writable:
            results.append(self._check_writable(path, fail_sev))

        return results

    def _check_reachable(self, path: str, fail_sev: Severity) -> CheckResult:
        try:
            result = subprocess.run(
                ["stat", path],
                capture_output=True, timeout=_TIMEOUT,
            )
            if result.returncode == 0:
                return CheckResult(
                    name=f"mounts:{path}:reachable",
                    severity=Severity.OK,
                    message="reachable",
                )
            return CheckResult(
                name=f"mounts:{path}:reachable",
                severity=fail_sev,
                message="stat failed",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"mounts:{path}:reachable",
                severity=fail_sev,
                message="timeout (possible stale mount)",
            )

    def _check_writable(self, path: str, fail_sev: Severity) -> CheckResult:
        try:
            result = subprocess.run(
                ["test", "-w", path],
                capture_output=True, timeout=_TIMEOUT,
            )
            if result.returncode == 0:
                return CheckResult(
                    name=f"mounts:{path}:writable",
                    severity=Severity.OK,
                    message="writable",
                )
            return CheckResult(
                name=f"mounts:{path}:writable",
                severity=fail_sev,
                message="not writable",
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"mounts:{path}:writable",
                severity=fail_sev,
                message="timeout checking write access",
            )
