"""Tests for the filesystem mount check."""

import subprocess
from unittest.mock import patch, mock_open, MagicMock

import pytest

from labwatch.checks.mounts_check import MountsCheck
from labwatch.models import Severity


def _cfg(mounts=None, enabled=True):
    return {
        "checks": {
            "mounts": {
                "enabled": enabled,
                "mounts": mounts or [],
            },
        },
    }


PROC_MOUNTS = """\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
192.168.1.10:/share /mnt/nas nfs4 rw,relatime 0 0
//server/backup /mnt/backup cifs rw,relatime 0 0
tmpfs /mnt/path\\040with\\040spaces tmpfs rw 0 0
"""


class TestMountedAndReachable:
    """Mount found in /proc/mounts and stat succeeds -> 2 OK results."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_two_ok_results(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{"path": "/mnt/nas"}]))
            results = check.run()

        assert len(results) == 2

        mounted = next(r for r in results if r.name == "mounts:/mnt/nas:mounted")
        assert mounted.severity == Severity.OK
        assert mounted.message == "mounted"

        reachable = next(r for r in results if r.name == "mounts:/mnt/nas:reachable")
        assert reachable.severity == Severity.OK
        assert reachable.message == "reachable"


class TestNotMounted:
    """Path not in /proc/mounts -> CRITICAL, no reachable check."""

    @patch("labwatch.checks.mounts_check.sys")
    def test_not_mounted_critical(self, mock_sys):
        mock_sys.platform = "linux"

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{"path": "/mnt/missing"}]))
            results = check.run()

        assert len(results) == 1
        assert results[0].name == "mounts:/mnt/missing:mounted"
        assert results[0].severity == Severity.CRITICAL
        assert results[0].message == "not mounted"


class TestStaleNFS:
    """Mount in /proc/mounts but stat times out (stale NFS) -> reachable CRITICAL."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_stat_timeout(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.side_effect = subprocess.TimeoutExpired(["stat", "/mnt/nas"], 10)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{"path": "/mnt/nas"}]))
            results = check.run()

        assert len(results) == 2

        mounted = next(r for r in results if r.name == "mounts:/mnt/nas:mounted")
        assert mounted.severity == Severity.OK

        reachable = next(r for r in results if r.name == "mounts:/mnt/nas:reachable")
        assert reachable.severity == Severity.CRITICAL
        assert "timeout" in reachable.message.lower()


class TestStatFails:
    """stat returns non-zero -> reachable fails."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_stat_nonzero(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=1)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{"path": "/mnt/nas"}]))
            results = check.run()

        reachable = next(r for r in results if r.name == "mounts:/mnt/nas:reachable")
        assert reachable.severity == Severity.CRITICAL
        assert "stat failed" in reachable.message


class TestWritablePass:
    """writable: true and test -w succeeds -> 3 OK results."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_writable_ok(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{
                "path": "/mnt/backup",
                "writable": True,
            }]))
            results = check.run()

        assert len(results) == 3

        writable = next(r for r in results if r.name == "mounts:/mnt/backup:writable")
        assert writable.severity == Severity.OK
        assert writable.message == "writable"


class TestWritableFail:
    """writable: true but test -w fails -> writable CRITICAL."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_writable_fail(self, mock_run, mock_sys):
        mock_sys.platform = "linux"

        def _side_effect(cmd, **kwargs):
            result = MagicMock(returncode=0)
            if cmd[0] == "test":
                result.returncode = 1
            return result

        mock_run.side_effect = _side_effect

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{
                "path": "/mnt/backup",
                "writable": True,
            }]))
            results = check.run()

        writable = next(r for r in results if r.name == "mounts:/mnt/backup:writable")
        assert writable.severity == Severity.CRITICAL
        assert writable.message == "not writable"


class TestWritableTimeout:
    """writable check times out -> writable CRITICAL."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_writable_timeout(self, mock_run, mock_sys):
        mock_sys.platform = "linux"

        def _side_effect(cmd, **kwargs):
            if cmd[0] == "test":
                raise subprocess.TimeoutExpired(cmd, 10)
            return MagicMock(returncode=0)

        mock_run.side_effect = _side_effect

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{
                "path": "/mnt/backup",
                "writable": True,
            }]))
            results = check.run()

        writable = next(r for r in results if r.name == "mounts:/mnt/backup:writable")
        assert writable.severity == Severity.CRITICAL
        assert "timeout" in writable.message.lower()


class TestEmptyMountsList:
    """Empty mounts list -> no results."""

    def test_empty(self):
        check = MountsCheck(_cfg([]))
        results = check.run()
        assert results == []


class TestNonLinux:
    """Non-Linux platform -> single UNKNOWN result."""

    @patch("labwatch.checks.mounts_check.sys")
    def test_non_linux(self, mock_sys):
        mock_sys.platform = "win32"
        check = MountsCheck(_cfg([{"path": "/mnt/nas"}]))
        results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN
        assert "non-Linux" in results[0].message


class TestSeverityOverride:
    """Severity override to warning."""

    @patch("labwatch.checks.mounts_check.sys")
    def test_warning_severity(self, mock_sys):
        mock_sys.platform = "linux"

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{
                "path": "/mnt/missing",
                "severity": "warning",
            }]))
            results = check.run()

        assert results[0].severity == Severity.WARNING


class TestPathWithSpaces:
    """Mount path with spaces is handled correctly."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_path_with_spaces(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{
                "path": "/mnt/path with spaces",
            }]))
            results = check.run()

        # Should find it in /proc/mounts and check reachable
        assert len(results) == 2
        mounted = next(r for r in results if ":mounted" in r.name)
        assert mounted.severity == Severity.OK


class TestMultipleMounts:
    """Multiple mounts are checked independently."""

    @patch("labwatch.checks.mounts_check.sys")
    @patch("labwatch.checks.mounts_check.subprocess.run")
    def test_multiple(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0)

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([
                {"path": "/mnt/nas"},
                {"path": "/mnt/backup"},
                {"path": "/mnt/missing"},
            ]))
            results = check.run()

        # /mnt/nas: mounted + reachable = 2
        # /mnt/backup: mounted + reachable = 2
        # /mnt/missing: not mounted = 1
        assert len(results) == 5

        nas_mounted = next(r for r in results if r.name == "mounts:/mnt/nas:mounted")
        assert nas_mounted.severity == Severity.OK

        missing = next(r for r in results if r.name == "mounts:/mnt/missing:mounted")
        assert missing.severity == Severity.CRITICAL


class TestProcMountsUnreadable:
    """If /proc/mounts can't be read, all mounts show as not mounted."""

    @patch("labwatch.checks.mounts_check.sys")
    def test_proc_mounts_oserror(self, mock_sys):
        mock_sys.platform = "linux"

        with patch("builtins.open", side_effect=OSError("permission denied")):
            check = MountsCheck(_cfg([{"path": "/mnt/nas"}]))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert results[0].message == "not mounted"


class TestEmptyPathSkipped:
    """Entry with empty path is skipped."""

    @patch("labwatch.checks.mounts_check.sys")
    def test_empty_path(self, mock_sys):
        mock_sys.platform = "linux"

        with patch("builtins.open", mock_open(read_data=PROC_MOUNTS)):
            check = MountsCheck(_cfg([{"path": ""}]))
            results = check.run()

        assert results == []
