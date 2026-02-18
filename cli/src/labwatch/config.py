"""Configuration loading, saving, and validation for labwatch."""

import os
import platform
import copy
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")


DEFAULT_CONFIG: Dict[str, Any] = {
    "hostname": platform.node() or "homelab",
    "notifications": {
        "min_severity": "warning",
        "ntfy": {
            "enabled": True,
            "server": "https://ntfy.sh",
            "topic": "homelab_alerts",
        },
    },
    "checks": {
        "system": {
            "enabled": True,
            "thresholds": {
                "disk_warning": 80,
                "disk_critical": 90,
                "memory_warning": 80,
                "memory_critical": 90,
                "cpu_warning": 80,
                "cpu_critical": 95,
            },
        },
        "docker": {
            "enabled": True,
            "watch_stopped": True,
            "containers": [],
        },
        "http": {
            "enabled": True,
            "endpoints": [],
        },
        "nginx": {
            "enabled": False,
            "container": "",
            "config_test": True,
            "endpoints": [],
        },
        "dns": {
            "enabled": False,
            "domains": [],
        },
        "ping": {
            "enabled": False,
            "hosts": [],
            "timeout": 5,
        },
        "home_assistant": {
            "enabled": False,
            "url": "http://localhost:8123",
            "external_url": "",
            "token": "",
            "google_home": True,
        },
        "systemd": {
            "enabled": False,
            "units": [],
        },
        "process": {
            "enabled": False,
            "names": [],
        },
        "command": {
            "enabled": False,
            "commands": [],
        },
        "network": {
            "enabled": False,
            "interfaces": [],
        },
        "updates": {
            "enabled": False,
            "warning_threshold": 1,
            "critical_threshold": 50,
        },
    },
    "update": {
        "compose_dirs": [],
    },
}


def default_config_path() -> Path:
    """Return the default config file path."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "labwatch" / "config.yaml"


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _expand_env_vars(obj):
    """Recursively expand ${VAR} references in string values."""
    if isinstance(obj, str):
        return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), obj)
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    return obj


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config from YAML file, merged with defaults.

    String values containing ``${VAR}`` are expanded from environment
    variables.  Unset variables are left as-is.
    """
    path = path or default_config_path()
    if not path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    with open(path, "r") as f:
        user_config = yaml.safe_load(f) or {}
    merged = deep_merge(DEFAULT_CONFIG, user_config)
    return _expand_env_vars(merged)


def save_config(config: Dict[str, Any], path: Optional[Path] = None) -> Path:
    """Save config dict to YAML file."""
    path = path or default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    return path


def validate_config(config: Dict[str, Any]) -> list:
    """Validate config and return a list of error strings (empty = valid)."""
    errors = []

    if not config.get("hostname"):
        errors.append("hostname is required")

    ntfy = config.get("notifications", {}).get("ntfy", {})
    if ntfy.get("enabled"):
        if not ntfy.get("server"):
            errors.append("notifications.ntfy.server is required when ntfy is enabled")
        if not ntfy.get("topic"):
            errors.append("notifications.ntfy.topic is required when ntfy is enabled")

    checks = config.get("checks", {})

    thresholds = checks.get("system", {}).get("thresholds", {})
    for key in ("disk_warning", "disk_critical", "memory_warning", "memory_critical"):
        val = thresholds.get(key)
        if val is not None and not (0 <= val <= 100):
            errors.append(f"checks.system.thresholds.{key} must be 0-100, got {val}")

    disk_warn = thresholds.get("disk_warning", 80)
    disk_crit = thresholds.get("disk_critical", 90)
    if disk_warn >= disk_crit:
        errors.append("disk_warning must be less than disk_critical")

    mem_warn = thresholds.get("memory_warning", 80)
    mem_crit = thresholds.get("memory_critical", 90)
    if mem_warn >= mem_crit:
        errors.append("memory_warning must be less than memory_critical")

    for key in ("cpu_warning", "cpu_critical"):
        val = thresholds.get(key)
        if val is not None and not (0 <= val <= 100):
            errors.append(f"checks.system.thresholds.{key} must be 0-100, got {val}")

    cpu_warn = thresholds.get("cpu_warning", 80)
    cpu_crit = thresholds.get("cpu_critical", 95)
    if cpu_warn >= cpu_crit:
        errors.append("cpu_warning must be less than cpu_critical")

    for ep in checks.get("http", {}).get("endpoints", []):
        if not ep.get("name"):
            errors.append("HTTP endpoint missing 'name'")
        if not ep.get("url"):
            errors.append(f"HTTP endpoint '{ep.get('name', '?')}' missing 'url'")

    for ep in checks.get("nginx", {}).get("endpoints", []):
        if not isinstance(ep, str) or not ep.strip():
            errors.append("nginx.endpoints must contain non-empty URL strings")
            break

    for domain in checks.get("dns", {}).get("domains", []):
        if not isinstance(domain, str) or not domain.strip():
            errors.append("dns.domains must contain non-empty strings")
            break

    for host in checks.get("ping", {}).get("hosts", []):
        if not isinstance(host, str) or not host.strip():
            errors.append("ping.hosts must contain non-empty strings")
            break

    ha_cfg = checks.get("home_assistant", {})
    if ha_cfg.get("enabled") and not ha_cfg.get("url"):
        errors.append("home_assistant.url is required when home_assistant is enabled")

    # Validate min_severity
    min_sev = config.get("notifications", {}).get("min_severity", "warning")
    if min_sev not in ("ok", "warning", "critical"):
        errors.append(
            f"notifications.min_severity must be one of: ok, warning, critical — got '{min_sev}'"
        )

    # Validate systemd units
    for i, unit in enumerate(checks.get("systemd", {}).get("units", [])):
        if isinstance(unit, str):
            if not unit.strip():
                errors.append(f"systemd.units[{i}] must be a non-empty string")
                break
        elif isinstance(unit, dict):
            if not unit.get("name"):
                errors.append(f"systemd.units[{i}] missing 'name'")
                break
            sev = unit.get("severity", "critical")
            if sev not in ("warning", "critical"):
                errors.append(f"systemd.units[{i}].severity must be 'warning' or 'critical'")
        else:
            errors.append(f"systemd.units[{i}] must be a string or dict with 'name'")
            break

    # Validate process names
    for i, name in enumerate(checks.get("process", {}).get("names", [])):
        if not isinstance(name, str) or not name.strip():
            errors.append("process.names must contain non-empty strings")
            break

    # Validate command checks
    for i, cmd in enumerate(checks.get("command", {}).get("commands", [])):
        if not cmd.get("name"):
            errors.append(f"command.commands[{i}] missing 'name'")
        if not cmd.get("command"):
            errors.append(f"command.commands[{i}] missing 'command'")
        sev = cmd.get("severity", "critical")
        if sev not in ("warning", "critical"):
            errors.append(
                f"command.commands[{i}].severity must be 'warning' or 'critical'"
            )

    # Validate network interfaces
    for i, iface in enumerate(checks.get("network", {}).get("interfaces", [])):
        if not isinstance(iface, dict) or not iface.get("name"):
            errors.append(f"network.interfaces[{i}] must be a dict with non-empty 'name'")
            continue
        sev = iface.get("severity", "critical")
        if sev not in ("warning", "critical"):
            errors.append(
                f"network.interfaces[{i}].severity must be 'warning' or 'critical'"
            )

    # Validate updates thresholds
    updates_cfg = checks.get("updates", {})
    if updates_cfg.get("enabled"):
        warn_t = updates_cfg.get("warning_threshold", 1)
        crit_t = updates_cfg.get("critical_threshold", 50)
        if not isinstance(warn_t, int) or warn_t < 0:
            errors.append("updates.warning_threshold must be a non-negative integer")
        if not isinstance(crit_t, int) or crit_t < 0:
            errors.append("updates.critical_threshold must be a non-negative integer")
        if isinstance(warn_t, int) and isinstance(crit_t, int) and warn_t >= crit_t:
            errors.append("updates.warning_threshold must be less than critical_threshold")

    compose_dirs = config.get("update", {}).get("compose_dirs", [])
    if not isinstance(compose_dirs, list):
        errors.append("update.compose_dirs must be a list")
    else:
        for i, d in enumerate(compose_dirs):
            if not isinstance(d, str) or not d.strip():
                errors.append(f"update.compose_dirs[{i}] must be a non-empty string")

    return errors
