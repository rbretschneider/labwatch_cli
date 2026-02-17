"""Tests for severity-based ntfy priority and min_severity filtering."""

from unittest.mock import patch, MagicMock

from labwatch.models import CheckReport, CheckResult, Severity
from labwatch.notifications.ntfy import NtfyNotifier
from labwatch.runner import Runner, SEVERITY_ORDER, SEVERITY_BY_NAME


class TestNtfyPriorityMapping:
    def _notifier(self):
        return NtfyNotifier({
            "server": "https://ntfy.sh",
            "topic": "test",
        })

    def test_critical_maps_to_high(self):
        n = self._notifier()
        assert n.SEVERITY_PRIORITY["critical"] == "high"

    def test_warning_maps_to_default(self):
        n = self._notifier()
        assert n.SEVERITY_PRIORITY["warning"] == "default"

    def test_ok_maps_to_low(self):
        n = self._notifier()
        assert n.SEVERITY_PRIORITY["ok"] == "low"

    def test_unknown_maps_to_low(self):
        n = self._notifier()
        assert n.SEVERITY_PRIORITY["unknown"] == "low"

    @patch("labwatch.notifications.ntfy.requests.post")
    def test_send_passes_priority_header(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        mock_post.return_value.raise_for_status = MagicMock()

        n = self._notifier()
        n.send("title", "body", severity="critical")

        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Priority"] == "high"

    @patch("labwatch.notifications.ntfy.requests.post")
    def test_send_default_severity(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        mock_post.return_value.raise_for_status = MagicMock()

        n = self._notifier()
        n.send("title", "body")

        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Priority"] == "low"


class TestSeverityOrder:
    def test_ordering(self):
        assert SEVERITY_ORDER[Severity.OK] < SEVERITY_ORDER[Severity.UNKNOWN]
        assert SEVERITY_ORDER[Severity.UNKNOWN] < SEVERITY_ORDER[Severity.WARNING]
        assert SEVERITY_ORDER[Severity.WARNING] < SEVERITY_ORDER[Severity.CRITICAL]

    def test_by_name_mapping(self):
        assert SEVERITY_BY_NAME["ok"] == Severity.OK
        assert SEVERITY_BY_NAME["critical"] == Severity.CRITICAL


class TestMinSeverityFiltering:
    def _config(self, min_severity="warning"):
        return {
            "hostname": "test",
            "notifications": {
                "min_severity": min_severity,
                "ntfy": {"enabled": True, "server": "https://ntfy.sh", "topic": "t"},
            },
            "checks": {},
        }

    def _report(self, *severities):
        report = CheckReport(hostname="test")
        for i, sev in enumerate(severities):
            report.results.append(CheckResult(
                name=f"check-{i}", severity=sev, message="msg",
            ))
        return report

    @patch("labwatch.runner.get_notifiers")
    def test_warning_filter_skips_ok(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("warning"))
        report = self._report(Severity.OK, Severity.OK)
        runner.notify(report)

        mock_send.assert_not_called()

    @patch("labwatch.runner.get_notifiers")
    def test_warning_filter_sends_on_warning(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("warning"))
        report = self._report(Severity.OK, Severity.WARNING)
        runner.notify(report)

        mock_send.assert_called_once()
        title, message = mock_send.call_args[0][:2]
        assert "WARNING" in title
        # OK result should be filtered out of the message
        assert "check-0" not in message
        assert "check-1" in message

    @patch("labwatch.runner.get_notifiers")
    def test_critical_filter_skips_warning(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("critical"))
        report = self._report(Severity.WARNING, Severity.OK)
        runner.notify(report)

        mock_send.assert_not_called()

    @patch("labwatch.runner.get_notifiers")
    def test_critical_filter_sends_on_critical(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("critical"))
        report = self._report(Severity.WARNING, Severity.CRITICAL)
        runner.notify(report)

        mock_send.assert_called_once()
        title, message = mock_send.call_args[0][:2]
        assert "CRITICAL" in title
        # WARNING should be filtered out
        assert "check-0" not in message
        assert "check-1" in message

    @patch("labwatch.runner.get_notifiers")
    def test_ok_filter_sends_everything(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("ok"))
        report = self._report(Severity.OK, Severity.WARNING)
        runner.notify(report)

        mock_send.assert_called_once()
        _, message = mock_send.call_args[0][:2]
        assert "check-0" in message
        assert "check-1" in message

    @patch("labwatch.runner.get_notifiers")
    def test_severity_passed_to_notifier(self, mock_notifiers):
        mock_send = MagicMock()
        notifier = MagicMock()
        notifier.send = mock_send
        mock_notifiers.return_value = [notifier]

        runner = Runner(self._config("warning"))
        report = self._report(Severity.CRITICAL, Severity.WARNING)
        runner.notify(report)

        kwargs = mock_send.call_args[1]
        assert kwargs["severity"] == "critical"
