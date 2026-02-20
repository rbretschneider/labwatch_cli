"""Tests for the new generic check modules: systemd, process, command."""

from unittest.mock import patch, MagicMock
import subprocess

from labwatch.checks.systemd_check import SystemdCheck
from labwatch.checks.process_check import ProcessCheck
from labwatch.checks.command_check import CommandCheck
from labwatch.models import Severity


def _make_config(check_name, check_cfg):
    return {"checks": {check_name: {"enabled": True, **check_cfg}}}


# --- SystemdCheck -----------------------------------------------------------

class TestSystemdCheck:
    def _run(self, units):
        cfg = _make_config("systemd", {"units": units})
        return SystemdCheck(cfg).run()

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_active_unit_ok(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="active\n")
        results = self._run(["nginx"])
        assert len(results) == 1
        assert results[0].severity == Severity.OK
        assert results[0].name == "systemd:nginx"

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_inactive_unit_critical(self, mock_run):
        mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n")
        results = self._run(["nginx"])
        assert results[0].severity == Severity.CRITICAL

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_severity_override_warning(self, mock_run):
        mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n")
        results = self._run([{"name": "caddy", "severity": "warning"}])
        assert results[0].severity == Severity.WARNING
        assert results[0].name == "systemd:caddy"

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_string_unit_entry(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="active\n")
        results = self._run(["docker"])
        assert results[0].name == "systemd:docker"

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_multiple_units(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="active\n"),
            MagicMock(returncode=3, stdout="failed\n"),
        ]
        results = self._run(["nginx", "broken"])
        assert len(results) == 2
        assert results[0].severity == Severity.OK
        assert results[1].severity == Severity.CRITICAL

    def test_empty_units_returns_nothing(self):
        results = self._run([])
        assert results == []

    @patch("labwatch.checks.systemd_check.subprocess.run", side_effect=FileNotFoundError)
    def test_systemctl_not_found(self, mock_run):
        results = self._run(["nginx"])
        assert results[0].severity == Severity.UNKNOWN
        assert "not available" in results[0].message

    @patch("labwatch.checks.systemd_check._is_root", True)
    @patch("labwatch.checks.systemd_check.subprocess.run",
           side_effect=subprocess.TimeoutExpired("systemctl", 10))
    def test_timeout(self, mock_run):
        results = self._run(["nginx"])
        assert results[0].severity == Severity.CRITICAL
        assert "Timeout" in results[0].message

    @patch("labwatch.checks.systemd_check._is_root", False)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_sudo_fallback_finds_active_unit(self, mock_run):
        """Non-root: plain systemctl returns inactive, sudo -n returns active."""
        mock_run.side_effect = [
            MagicMock(returncode=3, stdout="inactive\n"),   # plain
            MagicMock(returncode=0, stdout="active\n"),     # sudo -n
        ]
        results = self._run(["wg-quick@wg0"])
        assert results[0].severity == Severity.OK
        assert results[0].name == "systemd:wg-quick@wg0"
        # Verify sudo -n was attempted
        assert mock_run.call_count == 2
        assert mock_run.call_args_list[1][0][0][:2] == ["sudo", "-n"]

    @patch("labwatch.checks.systemd_check._is_root", False)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_sudo_fallback_also_fails(self, mock_run):
        """Non-root: both plain and sudo return inactive — report as failed."""
        mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n")
        results = self._run(["wg-quick@wg0"])
        assert results[0].severity == Severity.CRITICAL
        assert "inactive" in results[0].message

    @patch("labwatch.checks.systemd_check._is_root", False)
    @patch("labwatch.checks.systemd_check.subprocess.run")
    def test_sudo_fallback_sudo_missing(self, mock_run):
        """Non-root: sudo not installed — gracefully falls back."""
        mock_run.side_effect = [
            MagicMock(returncode=3, stdout="inactive\n"),   # plain
            FileNotFoundError("sudo"),                       # sudo missing
        ]
        results = self._run(["wg-quick@wg0"])
        assert results[0].severity == Severity.CRITICAL
        assert "inactive" in results[0].message


# --- ProcessCheck -----------------------------------------------------------

class TestProcessCheck:
    def _run(self, names):
        cfg = _make_config("process", {"names": names})
        return ProcessCheck(cfg).run()

    @patch("labwatch.checks.process_check.platform.system", return_value="Linux")
    @patch("labwatch.checks.process_check.subprocess.run")
    def test_running_process_ok(self, mock_run, mock_platform):
        mock_run.return_value = MagicMock(returncode=0)
        results = self._run(["redis-server"])
        assert len(results) == 1
        assert results[0].severity == Severity.OK
        assert results[0].name == "process:redis-server"

    @patch("labwatch.checks.process_check.platform.system", return_value="Linux")
    @patch("labwatch.checks.process_check.subprocess.run")
    def test_missing_process_critical(self, mock_run, mock_platform):
        mock_run.return_value = MagicMock(returncode=1)
        results = self._run(["ghost"])
        assert results[0].severity == Severity.CRITICAL

    @patch("labwatch.checks.process_check.platform.system", return_value="Windows")
    @patch("labwatch.checks.process_check.subprocess.run")
    def test_windows_tasklist_running(self, mock_run, mock_platform):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Image Name                     PID Session Name\nnginx.exe                     1234 Services",
        )
        results = self._run(["nginx"])
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.process_check.platform.system", return_value="Windows")
    @patch("labwatch.checks.process_check.subprocess.run")
    def test_windows_tasklist_not_running(self, mock_run, mock_platform):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="INFO: No tasks are running which match the specified criteria.",
        )
        results = self._run(["nginx"])
        assert results[0].severity == Severity.CRITICAL

    def test_empty_names_returns_nothing(self):
        results = self._run([])
        assert results == []

    @patch("labwatch.checks.process_check.platform.system", return_value="Linux")
    @patch("labwatch.checks.process_check.subprocess.run", side_effect=FileNotFoundError)
    def test_pgrep_not_found(self, mock_run, mock_platform):
        results = self._run(["redis"])
        assert results[0].severity == Severity.UNKNOWN

    @patch("labwatch.checks.process_check.platform.system", return_value="Linux")
    @patch("labwatch.checks.process_check.subprocess.run",
           side_effect=subprocess.TimeoutExpired("pgrep", 10))
    def test_timeout(self, mock_run, mock_platform):
        results = self._run(["redis"])
        assert results[0].severity == Severity.CRITICAL
        assert "Timeout" in results[0].message


# --- CommandCheck -----------------------------------------------------------

class TestCommandCheck:
    def _run(self, commands, verbose=False):
        cfg = _make_config("command", {"commands": commands})
        return CommandCheck(cfg, verbose=verbose).run()

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_exit_zero_ok(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        results = self._run([{"name": "test", "command": "echo ok"}])
        assert len(results) == 1
        assert results[0].severity == Severity.OK
        assert results[0].name == "command:test"

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_nonzero_exit_fails(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        results = self._run([{"name": "failing", "command": "false"}])
        assert results[0].severity == Severity.CRITICAL
        assert "Exit code 1" in results[0].message

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_custom_expected_exit(self, mock_run):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="")
        results = self._run([
            {"name": "weird", "command": "cmd", "expect_exit": 2},
        ])
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_expect_output_match(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="test is successful\n", stderr="",
        )
        results = self._run([
            {"name": "cfg", "command": "nginx -t", "expect_output": "successful"},
        ])
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_expect_output_miss(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="something else\n", stderr="",
        )
        results = self._run([
            {"name": "cfg", "command": "nginx -t", "expect_output": "successful"},
        ])
        assert results[0].severity == Severity.CRITICAL
        assert "missing expected string" in results[0].message

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_expect_output_checks_stderr_too(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr="successful\n",
        )
        results = self._run([
            {"name": "cfg", "command": "nginx -t", "expect_output": "successful"},
        ])
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_severity_override_warning(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        results = self._run([
            {"name": "soft", "command": "test", "severity": "warning"},
        ])
        assert results[0].severity == Severity.WARNING

    @patch("labwatch.checks.command_check.subprocess.run",
           side_effect=subprocess.TimeoutExpired("cmd", 30))
    def test_timeout(self, mock_run):
        results = self._run([{"name": "slow", "command": "sleep 60"}])
        assert results[0].severity == Severity.CRITICAL
        assert "timed out" in results[0].message

    def test_empty_commands_returns_nothing(self):
        results = self._run([])
        assert results == []

    def test_missing_name_skipped(self):
        results = self._run([{"command": "echo hi"}])
        assert results == []

    def test_missing_command_skipped(self):
        results = self._run([{"name": "noop"}])
        assert results == []

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_verbose_includes_details(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="details here", stderr="")
        results = self._run(
            [{"name": "verbose", "command": "fail"}],
            verbose=True,
        )
        assert results[0].details is not None
        assert "details here" in results[0].details

    @patch("labwatch.checks.command_check.subprocess.run")
    def test_non_verbose_no_details(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="details here", stderr="")
        results = self._run(
            [{"name": "quiet", "command": "fail"}],
            verbose=False,
        )
        assert results[0].details is None
