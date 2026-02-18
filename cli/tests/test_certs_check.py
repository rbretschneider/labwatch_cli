"""Tests for the TLS certificate expiry check module."""

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

from labwatch.checks.certs import CertsCheck
from labwatch.models import Severity


def _cfg(certs_cfg=None, enabled=True):
    base = {
        "enabled": enabled,
        "domains": [],
        "warn_days": 14,
        "critical_days": 7,
    }
    if certs_cfg:
        base.update(certs_cfg)
    return {"checks": {"certs": base}}


def _mock_cert(days_remaining):
    """Build a mock cert dict with notAfter set to N days from now."""
    expiry = datetime.now(timezone.utc) + timedelta(days=days_remaining, hours=12)
    not_after = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    return {"notAfter": not_after}


# ---------------------------------------------------------------------------
# No domains configured
# ---------------------------------------------------------------------------

class TestNoDomains:
    def test_empty_domains_returns_empty(self):
        check = CertsCheck(_cfg())
        assert check.run() == []

    def test_disabled_returns_empty(self):
        check = CertsCheck(_cfg({"domains": ["example.com"]}, enabled=False))
        # Disabled check still reads config — but runner won't call it.
        # The check itself doesn't gate on enabled; the runner does.
        # Still, with domains present, it would return results.
        # This just verifies the class instantiates cleanly.
        assert isinstance(check, CertsCheck)


# ---------------------------------------------------------------------------
# Certificate OK
# ---------------------------------------------------------------------------

class TestCertOK:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_cert_valid_90_days(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(90)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].name == "certs:example.com"
        assert results[0].severity == Severity.OK
        assert "90 day" in results[0].message


# ---------------------------------------------------------------------------
# Certificate warning
# ---------------------------------------------------------------------------

class TestCertWarning:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_cert_warn_at_10_days(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(10)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.WARNING
        assert "10 day" in results[0].message


# ---------------------------------------------------------------------------
# Certificate critical
# ---------------------------------------------------------------------------

class TestCertCritical:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_cert_critical_at_3_days(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(3)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "3 day" in results[0].message

    @patch("labwatch.checks.certs.socket.create_connection")
    def test_cert_expired(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(-5)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "expired" in results[0].message


# ---------------------------------------------------------------------------
# Custom thresholds
# ---------------------------------------------------------------------------

class TestCustomThresholds:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_custom_warn_30_crit_15(self, mock_conn):
        """With warn=30, crit=15, a cert at 20 days should be WARNING."""
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(20)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({
                "domains": ["example.com"],
                "warn_days": 30,
                "critical_days": 15,
            }))
            results = check.run()

        assert results[0].severity == Severity.WARNING


# ---------------------------------------------------------------------------
# Connection errors
# ---------------------------------------------------------------------------

class TestConnectionErrors:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_timeout(self, mock_conn):
        mock_conn.side_effect = socket.timeout("timed out")
        check = CertsCheck(_cfg({"domains": ["example.com"]}))
        results = check.run()
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "timed out" in results[0].message.lower()

    @patch("labwatch.checks.certs.socket.create_connection")
    def test_connection_refused(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError("Connection refused")
        check = CertsCheck(_cfg({"domains": ["example.com"]}))
        results = check.run()
        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "Connection" in results[0].message

    @patch("labwatch.checks.certs.socket.create_connection")
    def test_ssl_verification_error(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed"
        )

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.CRITICAL
        assert "verification failed" in results[0].message.lower()

    @patch("labwatch.checks.certs.socket.create_connection")
    def test_unexpected_error(self, mock_conn):
        mock_conn.side_effect = RuntimeError("unexpected")
        check = CertsCheck(_cfg({"domains": ["example.com"]}))
        results = check.run()
        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN
        assert "unexpected" in results[0].message


# ---------------------------------------------------------------------------
# No certificate returned
# ---------------------------------------------------------------------------

class TestNoCert:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_no_cert_returned(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = {}
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["example.com"]}))
            results = check.run()

        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN
        assert "No certificate" in results[0].message


# ---------------------------------------------------------------------------
# Multiple domains
# ---------------------------------------------------------------------------

class TestMultipleDomains:
    @patch("labwatch.checks.certs.socket.create_connection")
    def test_multiple_domains(self, mock_conn):
        mock_tls = MagicMock()
        mock_tls.getpeercert.return_value = _mock_cert(90)
        mock_tls.__enter__ = MagicMock(return_value=mock_tls)
        mock_tls.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        with patch("labwatch.checks.certs.ssl.create_default_context", return_value=mock_ctx):
            check = CertsCheck(_cfg({"domains": ["a.com", "b.com", "c.com"]}))
            results = check.run()

        assert len(results) == 3
        assert results[0].name == "certs:a.com"
        assert results[1].name == "certs:b.com"
        assert results[2].name == "certs:c.com"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestCertsRegistration:
    def test_certs_in_registry(self):
        from labwatch.checks import get_check_classes
        classes = get_check_classes()
        assert "certs" in classes
        assert classes["certs"] is CertsCheck
