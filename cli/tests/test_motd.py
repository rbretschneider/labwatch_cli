"""Tests for the labwatch motd command."""

from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from labwatch.cli import cli
from labwatch.models import CheckResult, CheckReport, Severity


def _make_report(hostname, results):
    report = CheckReport(hostname=hostname)
    report.results = results
    return report


class TestMotdCommand:

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_all_ok(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [
            CheckResult(name="updates", severity=Severity.OK, message="System is up to date"),
            CheckResult(name="disk:/", severity=Severity.OK, message="45% used"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd"])
        assert result.exit_code == 0
        assert "labwatch | myserver" in result.output
        assert "[+] updates:" in result.output
        assert "[+] disk:/:" in result.output
        assert "All checks passed" in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_with_warnings(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [
            CheckResult(name="updates", severity=Severity.WARNING, message="12 pending updates"),
            CheckResult(name="disk:/", severity=Severity.OK, message="45% used"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd"])
        assert result.exit_code == 0
        assert "[!] updates:" in result.output
        assert "12 pending updates" in result.output
        assert "All checks passed" not in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_with_critical(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [
            CheckResult(name="network:tun0:link", severity=Severity.CRITICAL, message="DOWN"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd"])
        assert result.exit_code == 0
        assert "[X] network:tun0:link:" in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_no_checks_ran(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd"])
        assert result.exit_code == 0
        assert "No checks ran" in result.output

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_only_flag(self, mock_run, mock_cfg):
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [
            CheckResult(name="updates", severity=Severity.OK, message="System is up to date"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd", "--only", "updates"])
        assert result.exit_code == 0
        # Verify the runner was called (it got the modules arg)
        mock_run.assert_called_once()

    @patch("labwatch.cli.load_config")
    @patch("labwatch.runner.Runner.run")
    def test_motd_plain_text_no_rich(self, mock_run, mock_cfg):
        """MOTD output should be plain text, no Rich markup."""
        mock_cfg.return_value = {"hostname": "myserver", "checks": {}}
        mock_run.return_value = _make_report("myserver", [
            CheckResult(name="cpu", severity=Severity.OK, message="5%"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["motd"])
        # Should not contain Rich formatting tags
        assert "[green]" not in result.output
        assert "[red]" not in result.output
        assert "[bold]" not in result.output
