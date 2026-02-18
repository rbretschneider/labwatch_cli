"""Tests for S.M.A.R.T. config validation and defaults."""

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


# ---------------------------------------------------------------------------
# DEFAULT_CONFIG has smart section
# ---------------------------------------------------------------------------

class TestSmartDefaults:
    def test_smart_in_default_config(self):
        assert "smart" in DEFAULT_CONFIG["checks"]

    def test_smart_disabled_by_default(self):
        assert DEFAULT_CONFIG["checks"]["smart"]["enabled"] is False

    def test_smart_default_thresholds(self):
        smart = DEFAULT_CONFIG["checks"]["smart"]
        assert smart["temp_warning"] == 50
        assert smart["temp_critical"] == 60
        assert smart["wear_warning"] == 80
        assert smart["wear_critical"] == 90

    def test_smart_default_devices_empty(self):
        assert DEFAULT_CONFIG["checks"]["smart"]["devices"] == []

    def test_default_config_validates(self):
        """Default config (with smart disabled) should pass validation."""
        assert validate_config(copy.deepcopy(DEFAULT_CONFIG)) == []


# ---------------------------------------------------------------------------
# Valid SMART configs
# ---------------------------------------------------------------------------

class TestSmartValidConfigs:
    def test_enabled_with_defaults(self):
        cfg = _cfg(**{"checks.smart.enabled": True})
        assert validate_config(cfg) == []

    def test_custom_thresholds(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 45,
                "temp_critical": 55,
                "wear_warning": 70,
                "wear_critical": 85,
                "devices": [],
            },
        })
        assert validate_config(cfg) == []

    def test_with_explicit_devices(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": ["/dev/sda", "/dev/nvme0"],
            },
        })
        assert validate_config(cfg) == []

    def test_disabled_skips_validation(self):
        """When disabled, even bad thresholds should not generate errors."""
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": False,
                "temp_warning": 999,
                "temp_critical": -1,
                "wear_warning": 200,
                "wear_critical": -50,
                "devices": "not a list",
            },
        })
        # Should be empty — validation only runs when enabled
        assert validate_config(cfg) == []


# ---------------------------------------------------------------------------
# Invalid temperature thresholds
# ---------------------------------------------------------------------------

class TestSmartTempValidation:
    def test_temp_warning_negative(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": -5,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("temp_warning" in e for e in errors)

    def test_temp_critical_negative(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": -1,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("temp_critical" in e for e in errors)

    def test_temp_warning_must_be_less_than_critical(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 65,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("temp_warning must be less than temp_critical" in e for e in errors)

    def test_temp_warning_equal_to_critical(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 60,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("temp_warning must be less than temp_critical" in e for e in errors)

    def test_temp_not_a_number(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": "hot",
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("temp_warning" in e for e in errors)


# ---------------------------------------------------------------------------
# Invalid wear thresholds
# ---------------------------------------------------------------------------

class TestSmartWearValidation:
    def test_wear_over_100(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 110,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("wear_warning" in e and "0-100" in e for e in errors)

    def test_wear_negative(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": -5,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("wear_critical" in e and "0-100" in e for e in errors)

    def test_wear_warning_must_be_less_than_critical(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 95,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("wear_warning must be less than wear_critical" in e for e in errors)

    def test_wear_equal(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 90,
                "wear_critical": 90,
                "devices": [],
            },
        })
        errors = validate_config(cfg)
        assert any("wear_warning must be less than wear_critical" in e for e in errors)


# ---------------------------------------------------------------------------
# Invalid devices
# ---------------------------------------------------------------------------

class TestSmartDevicesValidation:
    def test_devices_not_a_list(self):
        cfg = _cfg(**{
            "checks.smart": {
                "enabled": True,
                "temp_warning": 50,
                "temp_critical": 60,
                "wear_warning": 80,
                "wear_critical": 90,
                "devices": "/dev/sda",
            },
        })
        errors = validate_config(cfg)
        assert any("devices must be a list" in e for e in errors)
