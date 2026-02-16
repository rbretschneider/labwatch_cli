"""Cron schedule management for labwatch."""

import re
import shutil
import subprocess
import sys
from typing import List, Optional

# Marker suffix used to identify labwatch-managed cron entries
MARKER_PREFIX = "# labwatch:"

_INTERVAL_RE = re.compile(r"^(\d+)([mhd])$")


def parse_interval(interval: str) -> str:
    """Convert a human interval like '5m', '4h', '1d' to a cron expression.

    Supported formats:
      5m  → */5 * * * *
      4h  → 0 */4 * * *
      1d  → 0 0 * * *
    """
    match = _INTERVAL_RE.match(interval.strip())
    if not match:
        raise ValueError(
            f"Invalid interval '{interval}'. Use format like 5m, 4h, 1d."
        )

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "m":
        if value < 1 or value > 59:
            raise ValueError(f"Minute interval must be 1-59, got {value}")
        return f"*/{value} * * * *"
    elif unit == "h":
        if value < 1 or value > 23:
            raise ValueError(f"Hour interval must be 1-23, got {value}")
        return f"0 */{value} * * *"
    elif unit == "d":
        if value != 1:
            raise ValueError("Day interval only supports 1d (daily at midnight)")
        return "0 0 * * *"

    raise ValueError(f"Unknown unit '{unit}'")


def resolve_labwatch_path() -> str:
    """Find the absolute path to the labwatch executable.

    Tries shutil.which first, then falls back to 'python -m labwatch'.
    """
    path = shutil.which("labwatch")
    if path:
        return path
    # Fall back to running as a module with the current interpreter
    return f"{sys.executable} -m labwatch"


def _read_crontab() -> str:
    """Read the current user's crontab."""
    try:
        proc = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=10,
        )
        # crontab -l returns 1 with "no crontab for user" on some systems
        if proc.returncode != 0 and "no crontab" in proc.stderr.lower():
            return ""
        return proc.stdout
    except FileNotFoundError:
        raise RuntimeError("crontab command not found. Is cron installed?")
    except subprocess.TimeoutExpired:
        raise RuntimeError("crontab -l timed out")


def _write_crontab(content: str) -> None:
    """Write content as the user's crontab."""
    try:
        proc = subprocess.run(
            ["crontab", "-"],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"crontab write failed: {proc.stderr.strip()}")
    except FileNotFoundError:
        raise RuntimeError("crontab command not found. Is cron installed?")
    except subprocess.TimeoutExpired:
        raise RuntimeError("crontab write timed out")


def list_entries() -> List[str]:
    """Return all labwatch-managed cron entries."""
    _check_platform()
    crontab = _read_crontab()
    return [
        line for line in crontab.splitlines()
        if MARKER_PREFIX in line
    ]


def add_entry(subcommand: str, interval: str, modules: Optional[List[str]] = None) -> str:
    """Add (or replace) a labwatch cron entry for the given subcommand.

    If *modules* is provided (e.g. ["network", "dns"]), the entry is scoped
    to those check modules via ``--only`` and gets its own cron marker so it
    can coexist with other per-module entries.

    Returns the cron line that was added.
    """
    _check_platform()
    cron_expr = parse_interval(interval)
    labwatch_path = resolve_labwatch_path()

    if modules:
        modules_str = ",".join(sorted(modules))
        marker = f"{MARKER_PREFIX}{subcommand}:{modules_str}"
        cron_line = f"{cron_expr} {labwatch_path} {subcommand} --only {modules_str} {marker}"
    else:
        marker = f"{MARKER_PREFIX}{subcommand}"
        cron_line = f"{cron_expr} {labwatch_path} {subcommand} {marker}"

    crontab = _read_crontab()
    # Remove any existing entry with the exact same marker
    lines = [
        line for line in crontab.splitlines()
        if marker not in line
    ]
    lines.append(cron_line)

    # Ensure trailing newline
    new_crontab = "\n".join(lines).strip() + "\n"
    _write_crontab(new_crontab)
    return cron_line


def remove_entries(subcommand: Optional[str] = None) -> int:
    """Remove labwatch cron entries.

    If subcommand is given, only remove that entry.
    Otherwise, remove all labwatch entries.

    Returns the number of entries removed.
    """
    _check_platform()
    crontab = _read_crontab()
    lines = crontab.splitlines()

    if subcommand:
        marker = f"{MARKER_PREFIX}{subcommand}"
        new_lines = [line for line in lines if marker not in line]
    else:
        new_lines = [line for line in lines if MARKER_PREFIX not in line]

    removed = len(lines) - len(new_lines)

    if removed > 0:
        new_crontab = "\n".join(new_lines).strip() + "\n" if new_lines else ""
        _write_crontab(new_crontab)

    return removed


def _check_platform() -> None:
    """Raise an error on unsupported platforms."""
    if sys.platform == "win32":
        raise RuntimeError(
            "Cron scheduling is not supported on Windows. "
            "Use Task Scheduler instead."
        )
