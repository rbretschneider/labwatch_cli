"""Tests for new CLI features: exit codes, --quiet, --no-notify, --only validation,
enable/disable, doctor, and completion."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner
from rich.console import Console

from labwatch.cli import cli, _validate_modules
from labwatch.models import CheckResult, CheckReport, Severity


@pytest.fixture(autouse=True)
def _patch_console(monkeypatch):
    """Avoid the Windows-specific TextIOWrapper in _get_console during tests.

    Click's CliRunner replaces sys.stdout with a BytesIO mock that lacks
    .buffer, causing ValueError when _get_console wraps it on Windows.
    """
    monkeypatch.setattr(
        "labwatch.cli._get_console",
        lambda ctx: Console(no_color=True),
    )


def _make_report(hostname, results):
    report = CheckReport(hostname=hostname)
    report.results = results
    return report


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class TestCheckExitCodes:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_exit_0_on_all_ok(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.OK, message="fine"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check"])
        assert result.exit_code == 0

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_exit_1_on_warning(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.WARNING, message="80%"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--no-notify"])
        assert result.exit_code == 1

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_exit_2_on_critical(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.CRITICAL, message="95%"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--no-notify"])
        assert result.exit_code == 2

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_exit_2_when_mixed_warning_and_critical(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.WARNING, message="80%"),
            CheckResult(name="mem", severity=Severity.CRITICAL, message="99%"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--no-notify"])
        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# --quiet flag
# ---------------------------------------------------------------------------

class TestQuietFlag:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_quiet_suppresses_output_on_success(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.OK, message="fine"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["--quiet", "check"])
        assert result.exit_code == 0
        # Output should be empty or minimal when quiet and all OK
        assert "disk" not in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_quiet_shows_output_on_failure(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.WARNING, message="80%"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["--quiet", "check", "--no-notify"])
        # Should still show output when there are failures
        assert "disk" in result.output


# ---------------------------------------------------------------------------
# --no-notify flag
# ---------------------------------------------------------------------------

class TestNoNotifyFlag:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    @patch("labwatch.runner.Runner.notify")
    def test_no_notify_skips_notifications(self, mock_notify, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.WARNING, message="80%"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--no-notify"])
        mock_notify.assert_not_called()

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    @patch("labwatch.runner.Runner.notify")
    def test_without_no_notify_sends_notifications(self, mock_notify, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.WARNING, message="80%"),
        ])
        runner = CliRunner()
        runner.invoke(cli, ["check"])
        mock_notify.assert_called_once()


# ---------------------------------------------------------------------------
# --only module validation
# ---------------------------------------------------------------------------

class TestModuleValidation:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_valid_module_accepted(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--only", "system"])
        assert result.exit_code == 0

    @patch("labwatch.cli.load_config")
    def test_invalid_module_exits_with_error(self, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--only", "nonexistent_module_xyz"])
        assert result.exit_code == 1
        assert "Unknown check module" in result.output

    @patch("labwatch.cli.load_config")
    def test_invalid_module_shows_valid_list(self, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--only", "bogus"])
        assert "Valid modules:" in result.output
        assert "system" in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_comma_separated_modules(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--only", "system,docker"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# --json output
# ---------------------------------------------------------------------------

class TestJsonOutput:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_json_flag_produces_valid_json(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.OK, message="fine"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--json"])
        data = json.loads(result.output)
        assert data["hostname"] == "test"
        assert len(data["results"]) == 1
        assert data["results"][0]["severity"] == "ok"


# ---------------------------------------------------------------------------
# enable / disable commands
# ---------------------------------------------------------------------------

class TestEnableDisable:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.config.save_config")
    def test_enable_module(self, mock_save, mock_load, tmp_path):
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\nchecks:\n  docker:\n    enabled: false\n")

        mock_load.return_value = {
            "hostname": "test",
            "checks": {"docker": {"enabled": False}},
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(cfg_path), "enable", "docker"])
        assert result.exit_code == 0
        assert "enabled" in result.output
        mock_save.assert_called_once()
        saved_cfg = mock_save.call_args[0][0]
        assert saved_cfg["checks"]["docker"]["enabled"] is True

    @patch("labwatch.cli.load_config")
    @patch("labwatch.config.save_config")
    def test_disable_module(self, mock_save, mock_load, tmp_path):
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\nchecks:\n  docker:\n    enabled: true\n")

        mock_load.return_value = {
            "hostname": "test",
            "checks": {"docker": {"enabled": True}},
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(cfg_path), "disable", "docker"])
        assert result.exit_code == 0
        assert "disabled" in result.output
        saved_cfg = mock_save.call_args[0][0]
        assert saved_cfg["checks"]["docker"]["enabled"] is False

    @patch("labwatch.cli.load_config")
    def test_enable_invalid_module(self, mock_cfg):
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        runner = CliRunner()
        result = runner.invoke(cli, ["enable", "bogus_module"])
        assert result.exit_code == 1
        assert "Unknown check module" in result.output

    def test_enable_no_config_file(self, tmp_path):
        """Enable should fail gracefully when no config exists."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "--config", str(tmp_path / "nonexistent.yaml"),
            "enable", "system",
        ])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# doctor command
# ---------------------------------------------------------------------------

class TestDoctorCommand:
    @patch("labwatch.cli.load_config")
    def test_doctor_no_config_file(self, mock_cfg, tmp_path):
        """Doctor should fail when config doesn't exist."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "--config", str(tmp_path / "nonexistent.yaml"),
            "doctor",
        ])
        assert result.exit_code == 1
        assert "Config file not found" in result.output

    @patch("labwatch.cli.validate_config", return_value=[])
    @patch("labwatch.cli.load_config")
    def test_doctor_with_valid_config(self, mock_cfg, mock_validate, tmp_path):
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("hostname: test\n")

        mock_cfg.return_value = {
            "hostname": "test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {},
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(cfg_path), "doctor"])
        assert "Config file exists" in result.output
        assert "Config is valid" in result.output


# ---------------------------------------------------------------------------
# completion command
# ---------------------------------------------------------------------------

class TestCompletionCommand:
    def test_completion_invalid_shell(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["completion", "powershell"])
        assert result.exit_code != 0

    @patch("labwatch.cli.subprocess.run")
    def test_completion_bash(self, mock_run):
        mock_run.return_value = MagicMock(stdout="# bash completion\n", returncode=0)
        runner = CliRunner()
        result = runner.invoke(cli, ["completion", "bash"])
        assert result.exit_code == 0

    @patch("labwatch.cli.subprocess.run")
    def test_completion_fallback_when_no_stdout(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        runner = CliRunner()
        result = runner.invoke(cli, ["completion", "bash"])
        assert result.exit_code == 0
        assert "eval" in result.output


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

class TestVersionCommand:
    def test_version_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "labwatch" in result.output
