"""Tests for new CLI features: exit codes, --quiet, --no-notify, --only validation,
enable/disable, doctor, and completion."""

import io
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


# ---------------------------------------------------------------------------
# Lock integration
# ---------------------------------------------------------------------------

class TestCheckLockIntegration:
    @patch("labwatch.cli.load_config")
    @patch("labwatch.lock.Lock.acquire", return_value=False)
    def test_lock_held_exits_zero_no_output(self, mock_acquire, mock_cfg):
        """When another instance holds the lock, check exits 0 with no table."""
        mock_cfg.return_value = {"hostname": "test", "checks": {}}
        runner = CliRunner()
        result = runner.invoke(cli, ["check"])
        assert result.exit_code == 0
        assert "labwatch" not in result.output  # no Rich table

    @patch("labwatch.cli.load_config")
    @patch("labwatch.lock.Lock.acquire", return_value=False)
    def test_docker_update_lock_held_exits_zero(self, mock_acquire, mock_cfg):
        """docker-update should also exit 0 when locked."""
        mock_cfg.return_value = {"hostname": "test", "update": {"compose_dirs": ["/opt"]}}
        runner = CliRunner()
        result = runner.invoke(cli, ["docker-update"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Heartbeat integration
# ---------------------------------------------------------------------------

class TestCheckHeartbeatIntegration:
    @patch("labwatch.heartbeat.ping_heartbeat")
    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_heartbeat_called_after_check(self, mock_run, mock_cfg, mock_hb):
        mock_cfg.return_value = {
            "hostname": "test",
            "checks": {},
            "notifications": {"heartbeat_url": "https://hc-ping.com/abc"},
        }
        mock_run.return_value = _make_report("test", [
            CheckResult(name="disk", severity=Severity.OK, message="fine"),
        ])
        runner = CliRunner()
        result = runner.invoke(cli, ["check"])
        assert result.exit_code == 0
        mock_hb.assert_called_once()
        # Verify has_failures=False was passed
        assert mock_hb.call_args[0][1] is False or mock_hb.call_args[1].get("has_failures") is False


# ---------------------------------------------------------------------------
# Doctor cron verification
# ---------------------------------------------------------------------------

class TestVerifyCronEntries:
    """Unit tests for _verify_cron_entries (called by doctor)."""

    def _run(self, entries):
        """Run _verify_cron_entries and return (oks, warns, fails, output)."""
        from labwatch.cli import _verify_cron_entries

        oks, warns, fails = [], [], []
        console = Console(no_color=True, file=io.StringIO())

        _verify_cron_entries(
            entries, console,
            _ok=lambda m: oks.append(m),
            _warn=lambda m: warns.append(m),
            _fail=lambda m: fails.append(m),
        )
        output = console.file.getvalue()
        return oks, warns, fails, output

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_binary_exists(self, mock_run, mock_which, tmp_path):
        """Entry pointing to a real binary should pass."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")

        # Mock cron daemon check (active)
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        entry = f"*/5 * * * * {fake_bin} check # labwatch:check"
        oks, warns, fails, _ = self._run([entry])
        assert any("Binary exists" in m for m in oks)

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_binary_missing(self, mock_run, mock_which, tmp_path):
        """Entry pointing to a nonexistent binary should fail."""
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        entry = f"*/5 * * * * {tmp_path}/no_such_labwatch check # labwatch:check"
        oks, warns, fails, _ = self._run([entry])
        assert any("Binary not found" in m for m in fails)

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_sudo_nopasswd_ok(self, mock_run, mock_which, tmp_path):
        """sudo entry with working NOPASSWD should pass."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")

        # First call: cron daemon check. Subsequent: sudo -n -l check.
        mock_run.side_effect = [
            MagicMock(stdout="active\n", returncode=0),  # systemctl is-active cron
            MagicMock(stdout="", returncode=0),           # sudo -n -l labwatch system-update
        ]

        entry = f"0 0 * * 0 sudo {fake_bin} system-update # labwatch:system-update"
        oks, warns, fails, _ = self._run([entry])
        assert any("sudo NOPASSWD works" in m for m in oks)

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_sudo_requires_password(self, mock_run, mock_which, tmp_path):
        """sudo entry needing a password should fail."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")

        mock_run.side_effect = [
            MagicMock(stdout="active\n", returncode=0),  # systemctl is-active cron
            MagicMock(stdout="", stderr="password required", returncode=1),  # sudo -n -l
        ]

        entry = f"0 0 * * 0 sudo {fake_bin} system-update # labwatch:system-update"
        oks, warns, fails, _ = self._run([entry])
        assert any("sudo requires a password" in m for m in fails)

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_cron_daemon_not_running(self, mock_run, mock_which):
        """Should fail if cron daemon is not active and show fix hint."""
        mock_run.side_effect = [
            MagicMock(stdout="inactive\n", returncode=3),  # systemctl is-active cron
            MagicMock(stdout="inactive\n", returncode=3),  # systemctl is-active crond
        ]

        entry = "*/5 * * * * /usr/bin/labwatch check # labwatch:check"
        oks, warns, fails, output = self._run([entry])
        assert any("Cron daemon does not appear to be running" in m for m in fails)
        assert "systemctl enable --now cron" in output

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_sudo_password_shows_visudo_fix(self, mock_run, mock_which, tmp_path):
        """sudo failure should show copy-paste visudo fix."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")

        mock_run.side_effect = [
            MagicMock(stdout="active\n", returncode=0),
            MagicMock(stdout="", stderr="password required", returncode=1),
        ]

        entry = f"0 0 * * 0 sudo {fake_bin} system-update # labwatch:system-update"
        oks, warns, fails, output = self._run([entry])
        assert "visudo" in output
        assert "NOPASSWD" in output

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_binary_missing_shows_fix(self, mock_run, mock_which, tmp_path):
        """Missing binary should show schedule remove/re-add fix."""
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        entry = f"*/5 * * * * {tmp_path}/gone_labwatch check # labwatch:check"
        oks, warns, fails, output = self._run([entry])
        assert any("Binary not found" in m for m in fails)
        assert "schedule remove" in output

    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_deduplicates_same_binary(self, mock_run, mock_which, tmp_path):
        """Same binary across multiple entries should only be checked once."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")

        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        entries = [
            f"*/5 * * * * {fake_bin} check --only http # labwatch:check:http",
            f"*/30 * * * * {fake_bin} check --only system # labwatch:check:system",
            f"0 0 * * * {fake_bin} docker-update # labwatch:docker-update",
        ]
        oks, warns, fails, _ = self._run(entries)
        binary_oks = [m for m in oks if "Binary exists" in m]
        assert len(binary_oks) == 1  # reported once, not three times

    @patch("os.geteuid", create=True, return_value=1000)
    @patch("sys.platform", "linux")
    @patch("shutil.which", return_value="/usr/bin/systemctl")
    @patch("subprocess.run")
    def test_system_update_missing_sudo_warns(self, mock_run, mock_which, mock_euid, tmp_path):
        """system-update without sudo should warn when non-root."""
        fake_bin = tmp_path / "labwatch"
        fake_bin.write_text("#!/bin/sh\n")
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        entry = f"0 0 * * * {fake_bin} system-update # labwatch:system-update"
        oks, warns, fails, output = self._run([entry])
        assert any("missing sudo" in m for m in warns)
        assert "schedule remove system-update" in output
