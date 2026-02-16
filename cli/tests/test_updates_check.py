"""Tests for the updates check module."""

import subprocess
from unittest.mock import patch, MagicMock

from labwatch.checks.updates_check import UpdatesCheck
from labwatch.models import Severity


def _make_config(check_cfg):
    return {"checks": {"updates": {"enabled": True, **check_cfg}}}


APT_HEADER = "Listing...\n"
APT_ONE = APT_HEADER + "libssl3/jammy-updates 3.0.2-0ubuntu1.16 amd64 [upgradable from: 3.0.2-0ubuntu1.15]\n"
APT_MANY = APT_HEADER + "".join(
    f"pkg-{i}/jammy-updates 1.0.{i} amd64 [upgradable from: 1.0.{i-1}]\n"
    for i in range(1, 61)
)


class TestAptDetection:

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_no_updates_ok(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_HEADER, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert len(results) == 1
        assert results[0].severity == Severity.OK
        assert "up to date" in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_one_update_warning(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_ONE, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.WARNING
        assert "1 pending update" in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_many_updates_critical(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_MANY, stderr="",
        )
        cfg = _make_config({"critical_threshold": 50})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.CRITICAL
        assert "60 pending updates" in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_custom_thresholds(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_ONE, stderr="",
        )
        # warning_threshold=5 means 1 update is below warning -> OK
        cfg = _make_config({"warning_threshold": 5, "critical_threshold": 50})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_verbose_includes_details(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_ONE, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg, verbose=True).run()
        assert results[0].details is not None
        assert "libssl3" in results[0].details

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_non_verbose_no_details(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_ONE, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg, verbose=False).run()
        assert results[0].details is None

    @patch("labwatch.checks.updates_check.subprocess.run",
           side_effect=subprocess.TimeoutExpired("apt", 30))
    def test_apt_timeout(self, mock_run):
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.UNKNOWN
        assert "timed out" in results[0].message


class TestDnfDetection:

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_dnf_no_updates(self, mock_run):
        # apt not found, dnf returns 0 (no updates)
        def side_effect(cmd, **kwargs):
            if cmd[0] == "apt":
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.OK

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_dnf_updates_available(self, mock_run):
        dnf_output = "curl.x86_64  7.76.1-26.el9  baseos\nwget.x86_64  1.21.1-7.el9  appstream\n"

        def side_effect(cmd, **kwargs):
            if cmd[0] == "apt":
                raise FileNotFoundError
            return MagicMock(returncode=100, stdout=dnf_output, stderr="")

        mock_run.side_effect = side_effect
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.WARNING
        assert "2 pending updates" in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_dnf_timeout(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "apt":
                raise FileNotFoundError
            raise subprocess.TimeoutExpired("dnf", 60)

        mock_run.side_effect = side_effect
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.UNKNOWN
        assert "timed out" in results[0].message


class TestYumDetection:

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_yum_updates_available(self, mock_run):
        yum_output = "bash.x86_64  5.1.8-6.el8  baseos\n"

        def side_effect(cmd, **kwargs):
            if cmd[0] in ("apt", "dnf"):
                raise FileNotFoundError
            return MagicMock(returncode=100, stdout=yum_output, stderr="")

        mock_run.side_effect = side_effect
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.WARNING
        assert "1 pending update" in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_yum_timeout(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] in ("apt", "dnf"):
                raise FileNotFoundError
            raise subprocess.TimeoutExpired("yum", 60)

        mock_run.side_effect = side_effect
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.UNKNOWN
        assert "timed out" in results[0].message


class TestNoPackageManager:

    @patch("labwatch.checks.updates_check.subprocess.run",
           side_effect=FileNotFoundError)
    def test_no_manager_found(self, mock_run):
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert results[0].severity == Severity.UNKNOWN
        assert "No supported package manager" in results[0].message


class TestPluralLabel:

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_singular_label(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=APT_ONE, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert "1 pending update" in results[0].message
        assert "updates" not in results[0].message

    @patch("labwatch.checks.updates_check.subprocess.run")
    def test_plural_label(self, mock_run):
        two_pkgs = APT_HEADER + (
            "pkg-a/jammy 1.0 amd64 [upgradable from: 0.9]\n"
            "pkg-b/jammy 2.0 amd64 [upgradable from: 1.9]\n"
        )
        mock_run.return_value = MagicMock(
            returncode=0, stdout=two_pkgs, stderr="",
        )
        cfg = _make_config({})
        results = UpdatesCheck(cfg).run()
        assert "2 pending updates" in results[0].message
