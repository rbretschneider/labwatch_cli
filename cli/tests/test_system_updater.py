"""Tests for the system_updater module."""

import copy
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from labwatch.config import DEFAULT_CONFIG, validate_config
from labwatch.system_updater import SystemUpdater, SystemUpdateResult


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestConfigValidation:
    def test_valid_safe_mode(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["mode"] = "safe"
        errors = validate_config(cfg)
        assert not any("update.system" in e for e in errors)

    def test_valid_full_mode(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["mode"] = "full"
        errors = validate_config(cfg)
        assert not any("update.system" in e for e in errors)

    def test_invalid_mode_rejected(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["mode"] = "yolo"
        errors = validate_config(cfg)
        assert any("update.system.mode" in e for e in errors)

    def test_invalid_autoremove_rejected(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["autoremove"] = "yes"
        errors = validate_config(cfg)
        assert any("update.system.autoremove" in e for e in errors)

    def test_invalid_auto_reboot_rejected(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["auto_reboot"] = "yes"
        errors = validate_config(cfg)
        assert any("update.system.auto_reboot" in e for e in errors)

    def test_disabled_skips_validation(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = False
        cfg["update"]["system"]["mode"] = "invalid"
        errors = validate_config(cfg)
        assert not any("update.system.mode" in e for e in errors)


# ---------------------------------------------------------------------------
# Platform / privilege guards
# ---------------------------------------------------------------------------

class TestGuards:
    def _make_updater(self, **overrides):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"].update(overrides)
        return SystemUpdater(cfg)

    def test_windows_returns_error(self):
        updater = self._make_updater()
        with patch("labwatch.system_updater.sys.platform", "win32"):
            result = updater.run()
        assert result.error is not None
        assert "Windows" in result.error

    def test_not_root_returns_error(self):
        updater = self._make_updater()
        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=1000):
            result = updater.run()
        assert result.error is not None
        assert "root" in result.error


# ---------------------------------------------------------------------------
# apt-get update failure
# ---------------------------------------------------------------------------

class TestAptGetUpdate:
    def _make_updater(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        return SystemUpdater(cfg)

    def test_apt_update_failure(self):
        updater = self._make_updater()
        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=0), \
             patch("labwatch.system_updater.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, "apt-get", stderr=b"E: Some error"
            )
            result = updater.run()
        assert result.error is not None
        assert "apt-get update failed" in result.error

    def test_apt_update_timeout(self):
        updater = self._make_updater()
        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=0), \
             patch("labwatch.system_updater.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("apt-get", 300)
            result = updater.run()
        assert result.error is not None
        assert "timed out" in result.error


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_lists_packages(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        updater = SystemUpdater(cfg, dry_run=True)

        apt_list_output = (
            "Listing...\n"
            "vim/stable 9.0.1-1 amd64 [upgradable from: 8.2.1-1]\n"
            "curl/stable 7.88.1-1 amd64 [upgradable from: 7.87.0-1]\n"
        )

        mock_update = MagicMock()
        mock_list = MagicMock()
        mock_list.stdout = apt_list_output

        def run_side_effect(cmd, **kwargs):
            if cmd == ["apt-get", "update"]:
                return mock_update
            return mock_list

        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=0), \
             patch("labwatch.system_updater.subprocess.run", side_effect=run_side_effect):
            result = updater.run()

        assert result.dry_run is True
        assert "vim" in result.packages_upgraded
        assert "curl" in result.packages_upgraded
        assert result.error is None


# ---------------------------------------------------------------------------
# Upgrade modes
# ---------------------------------------------------------------------------

class TestUpgradeModes:
    def _run_upgrade(self, mode="safe"):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["mode"] = mode
        cfg["update"]["system"]["autoremove"] = False
        updater = SystemUpdater(cfg)

        upgrade_output = "Setting up vim (9.0.1-1) ...\n"

        calls = []

        def run_side_effect(cmd, **kwargs):
            calls.append(cmd)
            mock = MagicMock()
            mock.stdout = upgrade_output
            mock.returncode = 0
            return mock

        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=0), \
             patch("labwatch.system_updater.subprocess.run", side_effect=run_side_effect), \
             patch("labwatch.system_updater.os.path.exists", return_value=False):
            result = updater.run()

        return result, calls

    def test_safe_mode_calls_upgrade(self):
        result, calls = self._run_upgrade("safe")
        upgrade_cmds = [c for c in calls if "upgrade" in str(c)]
        assert any("upgrade" in c and "dist-upgrade" not in c for c in [str(x) for x in upgrade_cmds])
        assert result.error is None

    def test_full_mode_calls_dist_upgrade(self):
        result, calls = self._run_upgrade("full")
        assert any("dist-upgrade" in str(c) for c in calls)
        assert result.error is None


# ---------------------------------------------------------------------------
# Reboot detection
# ---------------------------------------------------------------------------

class TestRebootDetection:
    def _run_with_reboot(self, auto_reboot=False, reboot_file_exists=True):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["update"]["system"]["auto_reboot"] = auto_reboot
        cfg["update"]["system"]["autoremove"] = False
        updater = SystemUpdater(cfg)

        def run_side_effect(cmd, **kwargs):
            mock = MagicMock()
            mock.stdout = ""
            mock.returncode = 0
            return mock

        with patch("labwatch.system_updater.sys.platform", "linux"), \
             patch("labwatch.system_updater.os.geteuid", create=True, return_value=0), \
             patch("labwatch.system_updater.subprocess.run", side_effect=run_side_effect), \
             patch("labwatch.system_updater.os.path.exists", return_value=reboot_file_exists):
            result = updater.run()
        return result

    def test_reboot_required_detected(self):
        result = self._run_with_reboot(auto_reboot=False, reboot_file_exists=True)
        assert result.reboot_required is True
        assert result.rebooting is False

    def test_no_reboot_required(self):
        result = self._run_with_reboot(auto_reboot=False, reboot_file_exists=False)
        assert result.reboot_required is False
        assert result.rebooting is False

    def test_auto_reboot_sets_rebooting(self):
        result = self._run_with_reboot(auto_reboot=True, reboot_file_exists=True)
        assert result.reboot_required is True
        assert result.rebooting is True

    def test_auto_reboot_no_file_no_reboot(self):
        result = self._run_with_reboot(auto_reboot=True, reboot_file_exists=False)
        assert result.reboot_required is False
        assert result.rebooting is False


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class TestNotifications:
    def test_notify_on_success(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        cfg["notifications"]["ntfy"]["enabled"] = True
        updater = SystemUpdater(cfg)

        result = SystemUpdateResult(
            packages_upgraded=["vim", "curl"],
        )

        mock_notifier = MagicMock()
        with patch("labwatch.system_updater.get_notifiers", return_value=[mock_notifier]):
            updater.notify(result)

        mock_notifier.send.assert_called_once()
        title, message = mock_notifier.send.call_args[0]
        assert "completed" in title
        assert "2 package(s) upgraded" in message

    def test_notify_on_error(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        updater = SystemUpdater(cfg)

        result = SystemUpdateResult(error="apt-get update failed: E: Something")

        mock_notifier = MagicMock()
        with patch("labwatch.system_updater.get_notifiers", return_value=[mock_notifier]):
            updater.notify(result)

        mock_notifier.send.assert_called_once()
        title, message = mock_notifier.send.call_args[0]
        assert "failed" in title
        assert "apt-get update failed" in message

    def test_notify_with_reboot(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        updater = SystemUpdater(cfg)

        result = SystemUpdateResult(
            packages_upgraded=["linux-image"],
            reboot_required=True,
            rebooting=True,
        )

        mock_notifier = MagicMock()
        with patch("labwatch.system_updater.get_notifiers", return_value=[mock_notifier]):
            updater.notify(result)

        title, message = mock_notifier.send.call_args[0]
        assert "rebooting" in message

    def test_notify_reboot_required_no_auto(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        updater = SystemUpdater(cfg)

        result = SystemUpdateResult(
            packages_upgraded=["linux-image"],
            reboot_required=True,
            rebooting=False,
        )

        mock_notifier = MagicMock()
        with patch("labwatch.system_updater.get_notifiers", return_value=[mock_notifier]):
            updater.notify(result)

        title, message = mock_notifier.send.call_args[0]
        assert "reboot required" in message

    def test_notify_dry_run(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["update"]["system"]["enabled"] = True
        updater = SystemUpdater(cfg)

        result = SystemUpdateResult(
            packages_upgraded=["vim"],
            dry_run=True,
        )

        mock_notifier = MagicMock()
        with patch("labwatch.system_updater.get_notifiers", return_value=[mock_notifier]):
            updater.notify(result)

        title, message = mock_notifier.send.call_args[0]
        assert "dry-run" in title

    def test_no_notifiers_does_nothing(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        updater = SystemUpdater(cfg)
        result = SystemUpdateResult()
        # Should not raise
        with patch("labwatch.system_updater.get_notifiers", return_value=[]):
            updater.notify(result)


# ---------------------------------------------------------------------------
# do_reboot
# ---------------------------------------------------------------------------

class TestDoReboot:
    def test_do_reboot_calls_shutdown(self):
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        updater = SystemUpdater(cfg)
        with patch("labwatch.system_updater.subprocess.run") as mock_run:
            updater.do_reboot()
        mock_run.assert_called_once_with(
            ["shutdown", "-r", "+1"],
            capture_output=True, check=True, timeout=10,
        )
