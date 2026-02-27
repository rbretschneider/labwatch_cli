"""System package update engine for labwatch (Debian/DietPi apt-get)."""

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from labwatch.notifications import get_notifiers

_log = logging.getLogger("labwatch")

# Parse lines like "package/suite x.y.z amd64 [upgradable from: x.y.w]"
_APT_LIST_RE = re.compile(r"^(\S+?)(?:/\S+)?\s")

# Parse "Unpacking <pkg> ..." or "Setting up <pkg> ..." from apt output
_APT_UPGRADED_RE = re.compile(r"^(?:Unpacking|Setting up) (\S+)")

# Parse "Removing <pkg> ..." from autoremove output
_APT_REMOVED_RE = re.compile(r"^Removing (\S+)")


@dataclass
class SystemUpdateResult:
    """Result of a system package update run."""
    packages_upgraded: List[str] = field(default_factory=list)
    packages_removed: List[str] = field(default_factory=list)
    reboot_required: bool = False
    rebooting: bool = False
    error: Optional[str] = None
    dry_run: bool = False


class SystemUpdater:
    """Runs apt-get update/upgrade on Debian-based systems."""

    def __init__(self, config: dict, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        sys_cfg = config.get("update", {}).get("system", {})
        self.mode = sys_cfg.get("mode", "safe")
        self.autoremove = sys_cfg.get("autoremove", True)
        self.auto_reboot = sys_cfg.get("auto_reboot", False)

    def run(self) -> SystemUpdateResult:
        """Execute the full update sequence."""
        result = SystemUpdateResult(dry_run=self.dry_run)

        # Guard: Windows
        if sys.platform == "win32":
            result.error = "System updates are not supported on Windows"
            return result

        # Guard: must be root
        if os.geteuid() != 0:
            result.error = "System updates require root privileges (run with sudo)"
            return result

        # Step 1: apt-get update
        try:
            subprocess.run(
                ["apt-get", "update"],
                capture_output=True, check=True, timeout=300,
            )
        except subprocess.CalledProcessError as e:
            result.error = f"apt-get update failed: {e.stderr.decode(errors='replace').strip()}"
            return result
        except subprocess.TimeoutExpired:
            result.error = "apt-get update timed out after 300 seconds"
            return result

        # Step 2: dry-run — list upgradable packages and return
        if self.dry_run:
            try:
                proc = subprocess.run(
                    ["apt", "list", "--upgradable"],
                    capture_output=True, text=True, timeout=60,
                )
                for line in proc.stdout.splitlines():
                    m = _APT_LIST_RE.match(line)
                    if m and line != "Listing...":
                        result.packages_upgraded.append(m.group(1))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            return result

        # Step 3: apt-get upgrade or dist-upgrade
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        upgrade_cmd = "dist-upgrade" if self.mode == "full" else "upgrade"
        try:
            proc = subprocess.run(
                ["apt-get", upgrade_cmd, "-y"],
                capture_output=True, text=True, check=True, timeout=1800,
                env=env,
            )
            for line in proc.stdout.splitlines():
                m = _APT_UPGRADED_RE.match(line)
                if m:
                    pkg = m.group(1)
                    if pkg not in result.packages_upgraded:
                        result.packages_upgraded.append(pkg)
        except subprocess.CalledProcessError as e:
            result.error = f"apt-get {upgrade_cmd} failed: {e.stderr.strip()}"
            return result
        except subprocess.TimeoutExpired:
            result.error = f"apt-get {upgrade_cmd} timed out after 1800 seconds"
            return result

        # Step 4: optional autoremove
        if self.autoremove:
            try:
                proc = subprocess.run(
                    ["apt-get", "autoremove", "-y"],
                    capture_output=True, text=True, check=True, timeout=300,
                    env=env,
                )
                for line in proc.stdout.splitlines():
                    m = _APT_REMOVED_RE.match(line)
                    if m:
                        result.packages_removed.append(m.group(1))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass  # non-fatal

        # Step 5: check reboot required
        result.reboot_required = os.path.exists("/var/run/reboot-required")

        # Step 6: auto-reboot
        if self.auto_reboot and result.reboot_required:
            result.rebooting = True

        return result

    def notify(self, result: SystemUpdateResult) -> None:
        """Send a notification summarizing update results."""
        notifiers = get_notifiers(self.config)
        if not notifiers:
            return

        hostname = self.config.get("hostname", "unknown")

        if result.error:
            title = f"[{hostname}] System update failed"
            message = result.error
        elif result.dry_run:
            count = len(result.packages_upgraded)
            title = f"[{hostname}] System update dry-run"
            message = f"{count} package(s) upgradable"
        else:
            count = len(result.packages_upgraded)
            removed = len(result.packages_removed)
            parts = [f"{count} package(s) upgraded"]
            if removed:
                parts.append(f"{removed} removed")
            if result.rebooting:
                parts.append("rebooting in 1 minute")
            elif result.reboot_required:
                parts.append("reboot required")
            title = f"[{hostname}] System update completed"
            message = ", ".join(parts)

        _log.info("notified: %s — %s", title, message)
        for notifier in notifiers:
            try:
                notifier.send(title, message)
            except Exception as e:
                _log.warning("notification failed via %s: %s",
                             type(notifier).__name__, e)

    def do_reboot(self) -> None:
        """Schedule a reboot in 1 minute (gives time for notification to send)."""
        try:
            subprocess.run(
                ["shutdown", "-r", "+1"],
                capture_output=True, check=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
