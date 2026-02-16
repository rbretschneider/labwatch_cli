"""Tests for the network interface check."""

import subprocess
from unittest.mock import patch, mock_open, MagicMock

import pytest

from labwatch.checks.network_check import NetworkCheck
from labwatch.models import Severity


def _cfg(interfaces=None, enabled=True):
    return {
        "checks": {
            "network": {
                "enabled": enabled,
                "interfaces": interfaces or [],
            },
        },
    }


IP_LINK_UP = """\
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 500
    link/none"""

IP_LINK_DOWN = """\
3: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 500
    link/none"""

IP_ADDR_WITH_IP = """\
3: tun0    inet 10.8.0.2/24 brd 10.8.0.255 scope global tun0
       valid_lft forever preferred_lft forever"""

IP_ADDR_NO_IP = ""


def _run_side_effect(cmd, **kwargs):
    """Route subprocess.run calls based on command args."""
    completed = MagicMock(spec=subprocess.CompletedProcess)
    completed.returncode = 0

    if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
        # ip link (availability check)
        completed.stdout = ""
        return completed

    if cmd[:3] == ["ip", "link", "show"]:
        iface = cmd[3]
        completed.stdout = IP_LINK_UP.replace("tun0", iface)
        return completed

    if cmd[:4] == ["ip", "-4", "addr", "show"]:
        completed.stdout = IP_ADDR_WITH_IP
        return completed

    completed.stdout = ""
    return completed


class TestInterfaceUp:
    """Interface UP with IP and tx_bytes > 0 -> 3 OK results."""

    @patch("builtins.open", mock_open(read_data="12345\n"))
    @patch("labwatch.checks.network_check.subprocess.run", side_effect=_run_side_effect)
    def test_three_ok_results(self, mock_run):
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        assert len(results) == 3

        link = next(r for r in results if r.name == "network:tun0:link")
        assert link.severity == Severity.OK
        assert link.message == "UP"

        addr = next(r for r in results if r.name == "network:tun0:addr")
        assert addr.severity == Severity.OK
        assert "10.8.0.2" in addr.message

        tx = next(r for r in results if r.name == "network:tun0:tx")
        assert tx.severity == Severity.OK
        assert "12345" in tx.message


class TestInterfaceDown:
    """Interface DOWN -> link CRITICAL, addr check still runs."""

    def _run_down(self, cmd, **kwargs):
        completed = MagicMock(spec=subprocess.CompletedProcess)
        completed.returncode = 0
        if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
            completed.stdout = ""
            return completed
        if cmd[:3] == ["ip", "link", "show"]:
            completed.stdout = IP_LINK_DOWN
            return completed
        if cmd[:4] == ["ip", "-4", "addr", "show"]:
            completed.stdout = IP_ADDR_NO_IP
            return completed
        completed.stdout = ""
        return completed

    @patch("builtins.open", side_effect=OSError("not on linux"))
    @patch("labwatch.checks.network_check.subprocess.run")
    def test_down_critical(self, mock_run, mock_file):
        mock_run.side_effect = self._run_down
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        link = next(r for r in results if r.name == "network:tun0:link")
        assert link.severity == Severity.CRITICAL
        assert link.message == "DOWN"

        addr = next(r for r in results if r.name == "network:tun0:addr")
        assert addr.severity == Severity.CRITICAL


class TestInterfaceNotFound:
    """Interface not found -> CRITICAL."""

    def _run_not_found(self, cmd, **kwargs):
        completed = MagicMock(spec=subprocess.CompletedProcess)
        if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
            completed.returncode = 0
            completed.stdout = ""
            return completed
        if cmd[:3] == ["ip", "link", "show"]:
            completed.returncode = 1
            completed.stdout = ""
            completed.stderr = "Device does not exist."
            return completed
        if cmd[:4] == ["ip", "-4", "addr", "show"]:
            completed.returncode = 0
            completed.stdout = ""
            return completed
        completed.returncode = 0
        completed.stdout = ""
        return completed

    @patch("builtins.open", side_effect=OSError)
    @patch("labwatch.checks.network_check.subprocess.run")
    def test_not_found(self, mock_run, mock_file):
        mock_run.side_effect = self._run_not_found
        check = NetworkCheck(_cfg([{"name": "ghost0"}]))
        results = check.run()

        link = next(r for r in results if r.name == "network:ghost0:link")
        assert link.severity == Severity.CRITICAL
        assert "not found" in link.message


class TestNoIpAssigned:
    """Interface UP but no IP -> addr CRITICAL."""

    def _run_no_ip(self, cmd, **kwargs):
        completed = MagicMock(spec=subprocess.CompletedProcess)
        completed.returncode = 0
        if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
            completed.stdout = ""
            return completed
        if cmd[:3] == ["ip", "link", "show"]:
            completed.stdout = IP_LINK_UP
            return completed
        if cmd[:4] == ["ip", "-4", "addr", "show"]:
            completed.stdout = ""
            return completed
        completed.stdout = ""
        return completed

    @patch("builtins.open", side_effect=OSError)
    @patch("labwatch.checks.network_check.subprocess.run")
    def test_no_ip(self, mock_run, mock_file):
        mock_run.side_effect = self._run_no_ip
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        addr = next(r for r in results if r.name == "network:tun0:addr")
        assert addr.severity == Severity.CRITICAL
        assert "No IP" in addr.message


class TestTxBytesZero:
    """tx_bytes = 0 -> tx CRITICAL."""

    @patch("builtins.open", mock_open(read_data="0\n"))
    @patch("labwatch.checks.network_check.subprocess.run", side_effect=_run_side_effect)
    def test_zero_tx(self, mock_run):
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        tx = next(r for r in results if r.name == "network:tun0:tx")
        assert tx.severity == Severity.CRITICAL
        assert "0 bytes" in tx.message


class TestTxBytesMissing:
    """tx_bytes file not readable -> tx check skipped."""

    @patch("builtins.open", side_effect=OSError("no such file"))
    @patch("labwatch.checks.network_check.subprocess.run", side_effect=_run_side_effect)
    def test_tx_skipped(self, mock_run, mock_file):
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        names = [r.name for r in results]
        assert "network:tun0:link" in names
        assert "network:tun0:addr" in names
        assert "network:tun0:tx" not in names


class TestSeverityOverride:
    """Severity override to warning."""

    @patch("builtins.open", side_effect=OSError)
    @patch("labwatch.checks.network_check.subprocess.run")
    def test_warning_severity(self, mock_run, mock_file):
        def _run_down(cmd, **kwargs):
            completed = MagicMock(spec=subprocess.CompletedProcess)
            completed.returncode = 0
            if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
                completed.stdout = ""
                return completed
            if cmd[:3] == ["ip", "link", "show"]:
                completed.stdout = IP_LINK_DOWN
                return completed
            if cmd[:4] == ["ip", "-4", "addr", "show"]:
                completed.stdout = ""
                return completed
            completed.stdout = ""
            return completed

        mock_run.side_effect = _run_down
        check = NetworkCheck(_cfg([{"name": "wg0", "severity": "warning"}]))
        results = check.run()

        link = next(r for r in results if r.name == "network:wg0:link")
        assert link.severity == Severity.WARNING

        addr = next(r for r in results if r.name == "network:wg0:addr")
        assert addr.severity == Severity.WARNING


class TestEmptyInterfaces:
    """Empty interfaces list -> no results."""

    def test_empty(self):
        check = NetworkCheck(_cfg([]))
        results = check.run()
        assert results == []


class TestIpNotFound:
    """ip command not available -> single UNKNOWN result."""

    @patch(
        "labwatch.checks.network_check.subprocess.run",
        side_effect=FileNotFoundError("ip not found"),
    )
    def test_ip_missing(self, mock_run):
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN
        assert "ip command" in results[0].message


class TestTimeout:
    """Timeout -> CRITICAL."""

    @patch("labwatch.checks.network_check.subprocess.run")
    def test_link_timeout(self, mock_run):
        def _run_timeout(cmd, **kwargs):
            completed = MagicMock(spec=subprocess.CompletedProcess)
            if cmd[:2] == ["ip", "link"] and len(cmd) == 2:
                completed.returncode = 0
                completed.stdout = ""
                return completed
            raise subprocess.TimeoutExpired(cmd, 10)

        mock_run.side_effect = _run_timeout
        check = NetworkCheck(_cfg([{"name": "tun0"}]))
        results = check.run()

        link = next(r for r in results if r.name == "network:tun0:link")
        assert link.severity == Severity.CRITICAL
        assert "Timeout" in link.message
