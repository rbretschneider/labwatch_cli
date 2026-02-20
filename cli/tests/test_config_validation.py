"""Tests for config validation of new check types and min_severity."""

import copy

from labwatch.config import validate_config, DEFAULT_CONFIG


def _cfg(**overrides):
    """Build a valid config, then apply overrides via dot-paths."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for path, val in overrides.items():
        keys = path.split(".")
        d = cfg
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = val
    return cfg


class TestMinSeverityValidation:
    def test_valid_warning(self):
        cfg = _cfg(**{"notifications.min_severity": "warning"})
        assert validate_config(cfg) == []

    def test_valid_critical(self):
        cfg = _cfg(**{"notifications.min_severity": "critical"})
        assert validate_config(cfg) == []

    def test_valid_ok(self):
        cfg = _cfg(**{"notifications.min_severity": "ok"})
        assert validate_config(cfg) == []

    def test_invalid_value(self):
        cfg = _cfg(**{"notifications.min_severity": "urgent"})
        errors = validate_config(cfg)
        assert any("min_severity" in e for e in errors)

    def test_default_passes(self):
        """Default config should pass validation."""
        assert validate_config(copy.deepcopy(DEFAULT_CONFIG)) == []


class TestSystemdValidation:
    def test_string_units_valid(self):
        cfg = _cfg(**{
            "checks.systemd": {"enabled": True, "units": ["nginx", "docker"]},
        })
        assert validate_config(cfg) == []

    def test_dict_units_valid(self):
        cfg = _cfg(**{
            "checks.systemd": {
                "enabled": True,
                "units": [{"name": "nginx", "severity": "warning"}],
            },
        })
        assert validate_config(cfg) == []

    def test_empty_string_unit_rejected(self):
        cfg = _cfg(**{
            "checks.systemd": {"enabled": True, "units": [""]},
        })
        errors = validate_config(cfg)
        assert any("systemd.units" in e for e in errors)

    def test_dict_missing_name_rejected(self):
        cfg = _cfg(**{
            "checks.systemd": {"enabled": True, "units": [{"severity": "warning"}]},
        })
        errors = validate_config(cfg)
        assert any("missing 'name'" in e for e in errors)

    def test_invalid_severity_rejected(self):
        cfg = _cfg(**{
            "checks.systemd": {
                "enabled": True,
                "units": [{"name": "foo", "severity": "info"}],
            },
        })
        errors = validate_config(cfg)
        assert any("severity" in e for e in errors)


class TestProcessValidation:
    def test_valid_names(self):
        cfg = _cfg(**{
            "checks.process": {"enabled": True, "names": ["redis-server"]},
        })
        assert validate_config(cfg) == []

    def test_empty_name_rejected(self):
        cfg = _cfg(**{
            "checks.process": {"enabled": True, "names": ["ok", ""]},
        })
        errors = validate_config(cfg)
        assert any("process.names" in e for e in errors)


class TestCommandValidation:
    def test_valid_command(self):
        cfg = _cfg(**{
            "checks.command": {
                "enabled": True,
                "commands": [{"name": "test", "command": "echo hi"}],
            },
        })
        assert validate_config(cfg) == []

    def test_missing_name_rejected(self):
        cfg = _cfg(**{
            "checks.command": {
                "enabled": True,
                "commands": [{"command": "echo hi"}],
            },
        })
        errors = validate_config(cfg)
        assert any("missing 'name'" in e for e in errors)

    def test_missing_command_rejected(self):
        cfg = _cfg(**{
            "checks.command": {
                "enabled": True,
                "commands": [{"name": "test"}],
            },
        })
        errors = validate_config(cfg)
        assert any("missing 'command'" in e for e in errors)

    def test_invalid_severity_rejected(self):
        cfg = _cfg(**{
            "checks.command": {
                "enabled": True,
                "commands": [
                    {"name": "x", "command": "true", "severity": "info"},
                ],
            },
        })
        errors = validate_config(cfg)
        assert any("severity" in e for e in errors)

    def test_warning_severity_accepted(self):
        cfg = _cfg(**{
            "checks.command": {
                "enabled": True,
                "commands": [
                    {"name": "x", "command": "true", "severity": "warning"},
                ],
            },
        })
        assert validate_config(cfg) == []


class TestNetworkValidation:
    def test_valid_interfaces(self):
        cfg = _cfg(**{
            "checks.network": {
                "enabled": True,
                "interfaces": [
                    {"name": "tun0", "severity": "critical"},
                    {"name": "wg0", "severity": "warning"},
                ],
            },
        })
        assert validate_config(cfg) == []

    def test_missing_name_rejected(self):
        cfg = _cfg(**{
            "checks.network": {
                "enabled": True,
                "interfaces": [{"severity": "critical"}],
            },
        })
        errors = validate_config(cfg)
        assert any("network.interfaces" in e for e in errors)

    def test_non_dict_rejected(self):
        cfg = _cfg(**{
            "checks.network": {
                "enabled": True,
                "interfaces": ["tun0"],
            },
        })
        errors = validate_config(cfg)
        assert any("network.interfaces" in e for e in errors)

    def test_invalid_severity_rejected(self):
        cfg = _cfg(**{
            "checks.network": {
                "enabled": True,
                "interfaces": [{"name": "tun0", "severity": "info"}],
            },
        })
        errors = validate_config(cfg)
        assert any("severity" in e for e in errors)

    def test_empty_interfaces_valid(self):
        cfg = _cfg(**{
            "checks.network": {"enabled": True, "interfaces": []},
        })
        assert validate_config(cfg) == []

    def test_default_severity_valid(self):
        cfg = _cfg(**{
            "checks.network": {
                "enabled": True,
                "interfaces": [{"name": "eth0"}],
            },
        })
        assert validate_config(cfg) == []


class TestCertsValidation:
    def test_valid_certs_config(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": ["example.com"],
                "warn_days": 14,
                "critical_days": 7,
            },
        })
        assert validate_config(cfg) == []

    def test_empty_domain_rejected(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": ["good.com", ""],
                "warn_days": 14,
                "critical_days": 7,
            },
        })
        errors = validate_config(cfg)
        assert any("certs.domains" in e for e in errors)

    def test_warn_days_must_be_positive(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": [],
                "warn_days": 0,
                "critical_days": 7,
            },
        })
        errors = validate_config(cfg)
        assert any("warn_days" in e for e in errors)

    def test_critical_days_must_be_positive(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": [],
                "warn_days": 14,
                "critical_days": -1,
            },
        })
        errors = validate_config(cfg)
        assert any("critical_days" in e for e in errors)

    def test_warn_must_be_greater_than_critical(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": [],
                "warn_days": 7,
                "critical_days": 14,
            },
        })
        errors = validate_config(cfg)
        assert any("warn_days must be greater than critical_days" in e for e in errors)

    def test_warn_equal_to_critical_rejected(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": [],
                "warn_days": 7,
                "critical_days": 7,
            },
        })
        errors = validate_config(cfg)
        assert any("warn_days must be greater than critical_days" in e for e in errors)

    def test_empty_domains_valid(self):
        cfg = _cfg(**{
            "checks.certs": {
                "enabled": True,
                "domains": [],
                "warn_days": 14,
                "critical_days": 7,
            },
        })
        assert validate_config(cfg) == []

    def test_defaults_pass_validation(self):
        """Default certs config should pass validation."""
        assert validate_config(_cfg()) == []


class TestHeartbeatValidation:
    def test_empty_url_valid(self):
        cfg = _cfg(**{"notifications.heartbeat_url": ""})
        assert validate_config(cfg) == []

    def test_https_url_valid(self):
        cfg = _cfg(**{"notifications.heartbeat_url": "https://hc-ping.com/abc"})
        assert validate_config(cfg) == []

    def test_http_url_valid(self):
        cfg = _cfg(**{"notifications.heartbeat_url": "http://healthcheck.local/ping"})
        assert validate_config(cfg) == []

    def test_ftp_url_rejected(self):
        cfg = _cfg(**{"notifications.heartbeat_url": "ftp://example.com"})
        errors = validate_config(cfg)
        assert any("heartbeat_url" in e for e in errors)

    def test_non_string_rejected(self):
        cfg = _cfg(**{"notifications.heartbeat_url": 42})
        errors = validate_config(cfg)
        assert any("heartbeat_url" in e for e in errors)
