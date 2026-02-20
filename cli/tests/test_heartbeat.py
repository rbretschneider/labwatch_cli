"""Tests for the heartbeat (dead man's switch) module."""

from unittest.mock import patch, MagicMock

from labwatch.heartbeat import ping_heartbeat


class TestPingHeartbeat:
    def test_empty_url_skips(self):
        """No HTTP call when heartbeat_url is empty."""
        with patch("labwatch.heartbeat.requests.get") as mock_get:
            ping_heartbeat({"notifications": {"heartbeat_url": ""}}, False)
            mock_get.assert_not_called()

    def test_missing_url_skips(self):
        """No HTTP call when heartbeat_url is not in config at all."""
        with patch("labwatch.heartbeat.requests.get") as mock_get:
            ping_heartbeat({"notifications": {}}, False)
            mock_get.assert_not_called()

    def test_pings_url_on_success(self):
        """GET to the exact URL when no failures."""
        with patch("labwatch.heartbeat.requests.get") as mock_get:
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc"}},
                has_failures=False,
            )
            mock_get.assert_called_once_with("https://hc-ping.com/abc", timeout=10)

    def test_appends_fail_suffix(self):
        """Appends /fail when has_failures is True."""
        with patch("labwatch.heartbeat.requests.get") as mock_get:
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc"}},
                has_failures=True,
            )
            mock_get.assert_called_once_with("https://hc-ping.com/abc/fail", timeout=10)

    def test_fail_suffix_strips_trailing_slash(self):
        """Trailing slash on URL doesn't cause double-slash before /fail."""
        with patch("labwatch.heartbeat.requests.get") as mock_get:
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc/"}},
                has_failures=True,
            )
            mock_get.assert_called_once_with("https://hc-ping.com/abc/fail", timeout=10)

    def test_swallows_connection_error(self):
        """Network errors must not propagate — monitoring must not crash."""
        with patch("labwatch.heartbeat.requests.get", side_effect=ConnectionError("boom")):
            # Should not raise
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc"}},
                has_failures=False,
            )

    def test_swallows_timeout(self):
        """Timeout errors must not propagate."""
        import requests
        with patch("labwatch.heartbeat.requests.get", side_effect=requests.Timeout("slow")):
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc"}},
                has_failures=False,
            )

    def test_swallows_generic_exception(self):
        """Any exception at all must be swallowed."""
        with patch("labwatch.heartbeat.requests.get", side_effect=RuntimeError("wat")):
            ping_heartbeat(
                {"notifications": {"heartbeat_url": "https://hc-ping.com/abc"}},
                has_failures=False,
            )
