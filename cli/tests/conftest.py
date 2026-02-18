"""Shared fixtures for labwatch tests."""

import copy

import pytest

from labwatch.config import DEFAULT_CONFIG


@pytest.fixture
def default_cfg():
    """Return a deep copy of the default config."""
    return copy.deepcopy(DEFAULT_CONFIG)


@pytest.fixture
def full_cfg():
    """Return a config with every check type enabled and populated."""
    return {
        "hostname": "test-server",
        "notifications": {
            "min_severity": "warning",
            "ntfy": {
                "enabled": True,
                "server": "https://ntfy.example.com",
                "topic": "test_alerts",
            },
        },
        "checks": {
            "system": {
                "enabled": True,
                "thresholds": {
                    "disk_warning": 75,
                    "disk_critical": 90,
                    "memory_warning": 70,
                    "memory_critical": 95,
                    "cpu_warning": 80,
                    "cpu_critical": 95,
                },
            },
            "docker": {
                "enabled": True,
                "watch_stopped": True,
                "containers": ["plex", "grafana"],
            },
            "http": {
                "enabled": True,
                "endpoints": [
                    {"name": "HA", "url": "http://localhost:8123", "timeout": 10},
                    {"name": "Plex", "url": "http://localhost:32400/identity", "timeout": 5},
                ],
            },
            "nginx": {
                "enabled": True,
                "container": "nginx-proxy",
                "endpoints": ["https://example.com"],
            },
            "dns": {
                "enabled": True,
                "domains": ["google.com", "github.com"],
            },
            "ping": {
                "enabled": True,
                "hosts": ["8.8.8.8", "1.1.1.1"],
                "timeout": 3,
            },
            "home_assistant": {
                "enabled": True,
                "url": "http://ha.local:8123",
                "external_url": "https://ha.example.com",
                "token": "secret-token",
                "google_home": True,
            },
            "systemd": {
                "enabled": True,
                "units": [
                    "nginx",
                    {"name": "docker", "severity": "critical"},
                    {"name": "caddy", "severity": "warning"},
                ],
            },
            "process": {
                "enabled": True,
                "names": ["redis-server", "nginx"],
            },
            "command": {
                "enabled": True,
                "commands": [
                    {
                        "name": "nginx config",
                        "command": "nginx -t",
                        "expect_output": "successful",
                        "severity": "warning",
                    },
                    {
                        "name": "backup ran today",
                        "command": "find /backups -name '*.tar.gz' -mtime -1 | head -1",
                        "expect_exit": 0,
                    },
                ],
            },
            "network": {
                "enabled": True,
                "interfaces": [
                    {"name": "tun0", "severity": "critical"},
                    {"name": "wg0", "severity": "warning"},
                ],
            },
            "updates": {
                "enabled": True,
                "warning_threshold": 1,
                "critical_threshold": 50,
            },
            "smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": ["/dev/sda"],
            },
        },
        "update": {
            "compose_dirs": ["/opt/stacks/media", "/opt/stacks/monitoring"],
        },
    }
