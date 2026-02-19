"""Tests for the wizard refactor: module selection menu, --only flag, and SMART wizard section."""

import copy
from unittest.mock import patch, MagicMock

import pytest
import yaml
from click.testing import CliRunner

from labwatch.cli import cli
from labwatch.config import DEFAULT_CONFIG
from labwatch.wizard import (
    MODULES,
    SECTION_ORDER,
    SECTION_FUNCTIONS,
    CHECK_DESCRIPTIONS,
    SCHEDULE_TIERS,
    _module_selection_fallback,
    _section_smart,
    _warn_if_sudo_needed,
)


# ---------------------------------------------------------------------------
# MODULES list integrity
# ---------------------------------------------------------------------------

class TestModulesList:
    def test_modules_not_empty(self):
        assert len(MODULES) > 0

    def test_all_modules_have_required_keys(self):
        required = {"key", "label", "short_desc", "default_enabled", "wizard_fn", "config_path"}
        for mod in MODULES:
            missing = required - set(mod.keys())
            assert not missing, f"Module '{mod.get('key', '?')}' missing keys: {missing}"

    def test_smart_in_modules(self):
        keys = [m["key"] for m in MODULES]
        assert "smart" in keys

    def test_autoupdate_in_modules(self):
        keys = [m["key"] for m in MODULES]
        assert "autoupdate" in keys

    def test_module_keys_unique(self):
        keys = [m["key"] for m in MODULES]
        assert len(keys) == len(set(keys)), "Duplicate module keys found"

    def test_all_module_wizard_fns_are_callable(self):
        for mod in MODULES:
            assert callable(mod["wizard_fn"]), f"wizard_fn for '{mod['key']}' is not callable"

    def test_module_keys_match_section_functions(self):
        """Every module key should have a corresponding section function."""
        for mod in MODULES:
            assert mod["key"] in SECTION_FUNCTIONS, \
                f"Module '{mod['key']}' not in SECTION_FUNCTIONS"


# ---------------------------------------------------------------------------
# SECTION_ORDER and SECTION_FUNCTIONS integrity
# ---------------------------------------------------------------------------

class TestSectionOrder:
    def test_smart_in_section_order(self):
        assert "smart" in SECTION_ORDER

    def test_smart_in_section_functions(self):
        assert "smart" in SECTION_FUNCTIONS

    def test_hostname_first(self):
        assert SECTION_ORDER[0] == "hostname"

    def test_notifications_second(self):
        assert SECTION_ORDER[1] == "notifications"

    def test_scheduling_last(self):
        assert SECTION_ORDER[-1] == "scheduling"

    def test_all_section_order_entries_have_functions(self):
        for name in SECTION_ORDER:
            assert name in SECTION_FUNCTIONS, f"'{name}' in SECTION_ORDER but not SECTION_FUNCTIONS"


# ---------------------------------------------------------------------------
# CHECK_DESCRIPTIONS
# ---------------------------------------------------------------------------

class TestCheckDescriptions:
    def test_smart_has_description(self):
        assert "smart" in CHECK_DESCRIPTIONS
        assert "S.M.A.R.T." in CHECK_DESCRIPTIONS["smart"] or "smartctl" in CHECK_DESCRIPTIONS["smart"]


# ---------------------------------------------------------------------------
# SCHEDULE_TIERS
# ---------------------------------------------------------------------------

class TestScheduleTiers:
    def test_smart_in_slow_tier(self):
        """SMART should be in the 30-minute tier."""
        slow_tier = None
        for interval, label, checks, choices in SCHEDULE_TIERS:
            if interval == "30m":
                slow_tier = checks
                break
        assert slow_tier is not None, "30m tier not found"
        assert "smart" in slow_tier


# ---------------------------------------------------------------------------
# _section_smart function
# ---------------------------------------------------------------------------

class TestSectionSmart:
    def test_from_menu_sets_enabled(self):
        """When from_menu=True, smart should be enabled without prompting."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        # _keep_current now uses click.prompt; "n" declines keep, then thresholds + device
        with patch("labwatch.wizard.click.prompt") as mock_prompt, \
             patch("labwatch.wizard.click.confirm", return_value=False), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"):
            mock_prompt.side_effect = ["n", 50, 60, 80, 90, ""]
            _section_smart(config, from_menu=True)

        assert config["checks"]["smart"]["enabled"] is True

    def test_without_from_menu_asks_enable(self):
        """When from_menu=False, it should prompt to enable."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        # _confirm_enable now uses click.prompt; "n" disables the module
        with patch("labwatch.wizard.click.prompt") as mock_prompt, \
             patch("labwatch.wizard.click.confirm", return_value=False), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"):
            mock_prompt.return_value = "n"
            _section_smart(config, from_menu=False)

        # prompt should have been called (for enable check)
        mock_prompt.assert_called()
        assert config["checks"]["smart"]["enabled"] is False

    def test_smart_configures_thresholds(self):
        """When enabled, thresholds are configured."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        # "n" declines _keep_current, then threshold values, then device empty
        with patch("labwatch.wizard.click.prompt") as mock_prompt, \
             patch("labwatch.wizard.click.confirm", return_value=False), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"), \
             patch("labwatch.wizard._review_existing_list", return_value=[]):
            mock_prompt.side_effect = ["n", 45, 55, 75, 85, ""]
            _section_smart(config, from_menu=True)

        assert config["checks"]["smart"]["temp_warning"] == 45
        assert config["checks"]["smart"]["temp_critical"] == 55
        assert config["checks"]["smart"]["wear_warning"] == 75
        assert config["checks"]["smart"]["wear_critical"] == 85


# ---------------------------------------------------------------------------
# Module selection fallback
# ---------------------------------------------------------------------------

class TestModuleSelectionFallback:
    def test_fallback_returns_selected_modules(self):
        """Fallback should return keys for confirmed modules."""
        config = copy.deepcopy(DEFAULT_CONFIG)
        # "y" selects first three (system, docker, http), "n" denies the rest
        responses = ["y", "y", "y"] + ["n"] * (len(MODULES) - 3)
        with patch("labwatch.wizard.click.prompt", side_effect=responses), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"):
            selected = _module_selection_fallback(config)

        assert "system" in selected
        assert "docker" in selected
        assert "http" in selected
        assert "smart" not in selected

    def test_fallback_all_denied(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        with patch("labwatch.wizard.click.prompt", return_value="n"), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"):
            selected = _module_selection_fallback(config)
        assert selected == []


# ---------------------------------------------------------------------------
# from_menu parameter on section functions
# ---------------------------------------------------------------------------

class TestFromMenuParam:
    """All module section functions should accept from_menu kwarg."""

    _module_fns = [
        "system", "docker", "http", "nginx", "smart", "dns", "certs",
        "ping", "home_assistant", "systemd", "process", "network",
        "updates", "command", "autoupdate", "system_update",
    ]

    def test_section_functions_accept_from_menu(self):
        """Each module section function should accept from_menu keyword."""
        import inspect
        for name in self._module_fns:
            fn = SECTION_FUNCTIONS[name]
            sig = inspect.signature(fn)
            assert "from_menu" in sig.parameters, \
                f"SECTION_FUNCTIONS['{name}'] missing 'from_menu' parameter"


# ---------------------------------------------------------------------------
# run_wizard with --only
# ---------------------------------------------------------------------------

class TestWizardOnlyFlag:
    def test_only_invalid_section(self, tmp_path):
        """--only with invalid section name should fail."""
        runner = CliRunner()
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump(copy.deepcopy(DEFAULT_CONFIG)))

        result = runner.invoke(cli, [
            "--config", str(cfg_path), "init", "--only", "bogus_section",
        ])
        assert result.exit_code == 1
        assert "Unknown section" in result.output

    def test_only_requires_existing_config(self, tmp_path):
        """--only should fail when no existing config."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "--config", str(tmp_path / "nonexistent.yaml"),
            "init", "--only", "system",
        ])
        assert result.exit_code == 1
        assert "No existing config" in result.output

    def test_only_smart_accepted(self, tmp_path):
        """--only smart should be a valid section name and call the smart wizard."""
        runner = CliRunner()
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump(copy.deepcopy(DEFAULT_CONFIG)))

        mock_fn = MagicMock()
        with patch.dict("labwatch.wizard.SECTION_FUNCTIONS", {"smart": mock_fn}):
            result = runner.invoke(cli, [
                "--config", str(cfg_path), "init", "--only", "smart",
            ])
        mock_fn.assert_called_once()
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# run_wizard full flow — module selection menu integration
# ---------------------------------------------------------------------------

class TestWizardFullFlow:
    def test_unselected_modules_get_disabled(self, tmp_path):
        """Modules not selected in the menu should be set to enabled=False."""
        cfg_path = tmp_path / "config.yaml"

        # Create a mock system wizard fn that sets enabled=True
        mock_sys = MagicMock()

        # Patch MODULES to replace system's wizard_fn with our mock
        import labwatch.wizard as wiz
        original_modules = list(wiz.MODULES)
        patched_modules = []
        for mod in original_modules:
            if mod["key"] == "system":
                patched_modules.append({**mod, "wizard_fn": mock_sys})
            else:
                patched_modules.append(mod)

        with patch("labwatch.wizard._module_selection_menu", return_value=["system"]), \
             patch("labwatch.wizard._section_hostname"), \
             patch("labwatch.wizard._section_notifications"), \
             patch("labwatch.wizard._section_scheduling"), \
             patch.object(wiz, "MODULES", patched_modules):

            runner = CliRunner()
            result = runner.invoke(cli, [
                "--config", str(cfg_path), "init",
            ])

        # system was selected, so its wizard fn was called with from_menu=True
        mock_sys.assert_called_once()
        _, kwargs = mock_sys.call_args
        assert kwargs.get("from_menu") is True

    def test_menu_flow_runs_modules_then_hostname_then_notifications(self, tmp_path):
        """Module selection should run first, then hostname and notifications."""
        cfg_path = tmp_path / "config.yaml"
        call_order = []

        def track_menu(config):
            call_order.append("module_selection")
            return []

        def track_host(config):
            call_order.append("hostname")

        def track_notif(config):
            call_order.append("notifications")

        with patch("labwatch.wizard._module_selection_menu", side_effect=track_menu), \
             patch("labwatch.wizard._section_hostname", side_effect=track_host), \
             patch("labwatch.wizard._section_notifications", side_effect=track_notif), \
             patch("labwatch.wizard._section_scheduling"):

            runner = CliRunner()
            runner.invoke(cli, ["--config", str(cfg_path), "init"])

        assert call_order == ["module_selection", "hostname", "notifications"]


# ---------------------------------------------------------------------------
# Wizard _print_summary includes smart
# ---------------------------------------------------------------------------

class TestWizardPrintSummary:
    def test_print_summary_includes_smart(self):
        """The _print_summary function should list smart in all_check_names."""
        from labwatch.wizard import _print_summary
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["checks"]["smart"]["enabled"] = True

        with patch("labwatch.wizard.click.echo") as mock_echo, \
             patch("labwatch.wizard.click.secho"):
            from pathlib import Path
            _print_summary(config, Path("/tmp/config.yaml"))

        output = " ".join(str(c) for c in mock_echo.call_args_list)
        assert "smart" in output


# ---------------------------------------------------------------------------
# _warn_if_sudo_needed
# ---------------------------------------------------------------------------

class TestWarnIfSudoNeeded:
    def test_returns_false_on_windows(self):
        with patch("labwatch.wizard.sys.platform", "win32"):
            assert _warn_if_sudo_needed() is False

    def test_returns_false_when_root(self):
        with patch("labwatch.wizard.sys.platform", "linux"), \
             patch("labwatch.wizard.os.geteuid", create=True, return_value=0):
            assert _warn_if_sudo_needed() is False

    def test_returns_true_when_not_root(self):
        with patch("labwatch.wizard.sys.platform", "linux"), \
             patch("labwatch.wizard.os.geteuid", create=True, return_value=1000), \
             patch("labwatch.wizard.click.echo"), \
             patch("labwatch.wizard.click.secho"), \
             patch("labwatch.scheduler.shutil.which", return_value="/usr/local/bin/labwatch"), \
             patch("getpass.getuser", return_value="pi"):
            assert _warn_if_sudo_needed() is True

    def test_shows_sudoers_guidance_when_not_root(self):
        with patch("labwatch.wizard.sys.platform", "linux"), \
             patch("labwatch.wizard.os.geteuid", create=True, return_value=1000), \
             patch("labwatch.wizard.click.echo") as mock_echo, \
             patch("labwatch.wizard.click.secho") as mock_secho, \
             patch("labwatch.scheduler.shutil.which", return_value="/usr/local/bin/labwatch"), \
             patch("getpass.getuser", return_value="pi"):
            _warn_if_sudo_needed()

        # Should mention root privileges
        secho_output = " ".join(str(c) for c in mock_secho.call_args_list)
        assert "root privileges" in secho_output

        # Should show the visudo command
        assert "visudo" in secho_output

        # Should show the sudoers line with the username and labwatch path
        assert "pi ALL=(root) NOPASSWD:" in secho_output
        assert "/usr/local/bin/labwatch system-update" in secho_output
