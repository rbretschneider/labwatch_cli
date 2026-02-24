"""Tests for timezone detection and wizard/doctor integration."""

import subprocess
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from labwatch.wizard import _get_system_timezone, _check_timezone


# ---------------------------------------------------------------------------
# _get_system_timezone
# ---------------------------------------------------------------------------

class TestGetSystemTimezone:
    @patch("labwatch.wizard.Path.read_text", return_value="America/New_York\n")
    def test_reads_etc_timezone(self, mock_read):
        assert _get_system_timezone() == "America/New_York"

    @patch.dict("os.environ", {}, clear=False)
    @patch("labwatch.wizard.subprocess.run")
    @patch("labwatch.wizard.Path.read_text", side_effect=OSError)
    def test_falls_back_to_timedatectl(self, mock_read, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="US/Eastern\n")
        result = _get_system_timezone()
        assert result == "US/Eastern"
        mock_run.assert_called_once_with(
            ["timedatectl", "show", "--property=Timezone", "--value"],
            capture_output=True, text=True, timeout=5,
        )

    @patch.dict("os.environ", {"TZ": "Europe/London"}, clear=False)
    @patch("labwatch.wizard.subprocess.run", side_effect=FileNotFoundError)
    @patch("labwatch.wizard.Path.read_text", side_effect=OSError)
    def test_falls_back_to_env_var(self, mock_read, mock_run):
        assert _get_system_timezone() == "Europe/London"

    @patch.dict("os.environ", {}, clear=False)
    @patch("labwatch.wizard.subprocess.run", side_effect=FileNotFoundError)
    @patch("labwatch.wizard.Path.read_text", side_effect=OSError)
    def test_returns_none_when_all_fail(self, mock_read, mock_run):
        # Remove TZ if present
        import os
        os.environ.pop("TZ", None)
        assert _get_system_timezone() is None


# ---------------------------------------------------------------------------
# _check_timezone
# ---------------------------------------------------------------------------

class TestCheckTimezone:
    @patch("labwatch.wizard.sys")
    def test_skips_on_non_linux(self, mock_sys):
        mock_sys.platform = "win32"
        # Should return without doing anything
        _check_timezone()

    @patch("labwatch.wizard._prompt_yn", return_value=True)
    @patch("labwatch.wizard._get_system_timezone", return_value="America/New_York")
    @patch("labwatch.wizard.sys")
    def test_shows_timezone_and_accepts(self, mock_sys, mock_tz, mock_yn):
        mock_sys.platform = "linux"
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(_check_timezone_click_wrapper)
        assert "America/New_York" in result.output
        mock_yn.assert_called_once()

    @patch("labwatch.wizard.subprocess.run")
    @patch("labwatch.wizard.click.prompt", return_value="US/Pacific")
    @patch("labwatch.wizard._prompt_yn", return_value=False)
    @patch("labwatch.wizard._get_system_timezone", return_value="UTC")
    @patch("labwatch.wizard.sys")
    def test_offers_change_on_no(self, mock_sys, mock_tz, mock_yn, mock_prompt, mock_run):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(_check_timezone_click_wrapper)
        mock_run.assert_called_once_with(
            ["sudo", "timedatectl", "set-timezone", "US/Pacific"],
            check=True, capture_output=True, text=True,
        )

    @patch(
        "labwatch.wizard.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "timedatectl", stderr="Invalid timezone"),
    )
    @patch("labwatch.wizard.click.prompt", return_value="Bad/Zone")
    @patch("labwatch.wizard._prompt_yn", return_value=False)
    @patch("labwatch.wizard._get_system_timezone", return_value="UTC")
    @patch("labwatch.wizard.sys")
    def test_handles_timedatectl_failure(self, mock_sys, mock_tz, mock_yn, mock_prompt, mock_run):
        mock_sys.platform = "linux"
        runner = CliRunner()
        result = runner.invoke(_check_timezone_click_wrapper)
        assert "Failed to set timezone" in result.output

    @patch("labwatch.wizard._get_system_timezone", return_value=None)
    @patch("labwatch.wizard.sys")
    def test_returns_early_when_no_tz_detected(self, mock_sys, mock_tz):
        mock_sys.platform = "linux"
        runner = CliRunner()
        result = runner.invoke(_check_timezone_click_wrapper)
        # Should produce no timezone-related output
        assert "System timezone" not in result.output


# Helper: wrap _check_timezone in a click command so CliRunner can invoke it
import click

@click.command()
def _check_timezone_click_wrapper():
    _check_timezone()


# ---------------------------------------------------------------------------
# doctor timezone section
# ---------------------------------------------------------------------------

class TestDoctorTimezone:
    """Test the timezone section in doctor_cmd via CliRunner."""

    @patch("labwatch.wizard._get_system_timezone", return_value="America/New_York")
    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_shows_timezone(self, mock_cfg, mock_validate, mock_tz, tmp_path):
        from labwatch.cli import cli
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")
        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {},
        }
        runner = CliRunner()
        with patch("labwatch.cli.sys") as mock_sys:
            mock_sys.platform = "linux"
            mock_sys.stdout = MagicMock()
            mock_sys.stdout.buffer = MagicMock()
            result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "Timezone" in result.output
        assert "America/New_York" in result.output

    @patch("labwatch.wizard._get_system_timezone", return_value="UTC")
    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_warns_on_utc(self, mock_cfg, mock_validate, mock_tz, tmp_path):
        from labwatch.cli import cli
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")
        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {},
        }
        runner = CliRunner()
        with patch("labwatch.cli.sys") as mock_sys:
            mock_sys.platform = "linux"
            mock_sys.stdout = MagicMock()
            mock_sys.stdout.buffer = MagicMock()
            result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "UTC" in result.output
        assert "midnight UTC" in result.output

    @patch("labwatch.wizard._get_system_timezone", return_value="America/New_York")
    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_no_warn_on_local_tz(self, mock_cfg, mock_validate, mock_tz, tmp_path):
        from labwatch.cli import cli
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")
        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {},
        }
        runner = CliRunner()
        with patch("labwatch.cli.sys") as mock_sys:
            mock_sys.platform = "linux"
            mock_sys.stdout = MagicMock()
            mock_sys.stdout.buffer = MagicMock()
            result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "midnight UTC" not in result.output


# ---------------------------------------------------------------------------
# doctor mount tools section
# ---------------------------------------------------------------------------

class TestDoctorMountTools:
    """Test the mount-tools checks in the doctor System tools section."""

    @patch("labwatch.cli.Path.read_text", return_value="[Mount]\nOptions=credentials=/etc/samba/creds,rw\n")
    @patch("labwatch.wizard._get_system_timezone", return_value="America/New_York")
    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_checks_mount_cifs(self, mock_cfg, mock_validate, mock_tz, mock_override, tmp_path):
        from labwatch.cli import cli
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")
        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {
                "mounts": {
                    "enabled": True,
                    "mounts": [{"path": "/mnt/nas_Photos", "severity": "critical"}],
                },
            },
        }
        runner = CliRunner()
        with patch("labwatch.cli.sys") as mock_sys:
            mock_sys.platform = "linux"
            mock_sys.stdout = MagicMock()
            mock_sys.stdout.buffer = MagicMock()
            result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "mount.cifs" in result.output

    @patch("labwatch.wizard._get_system_timezone", return_value="America/New_York")
    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_skips_mount_tools_when_disabled(self, mock_cfg, mock_validate, mock_tz, tmp_path):
        from labwatch.cli import cli
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")
        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {},
        }
        runner = CliRunner()
        with patch("labwatch.cli.sys") as mock_sys:
            mock_sys.platform = "linux"
            mock_sys.stdout = MagicMock()
            mock_sys.stdout.buffer = MagicMock()
            result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "mount.cifs" not in result.output
        assert "mount.nfs" not in result.output
