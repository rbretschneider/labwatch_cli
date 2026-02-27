"""Tests for the logging setup module."""

import logging
from logging.handlers import RotatingFileHandler
from unittest.mock import patch

from labwatch.logging_setup import setup_logging, log_path


class TestSetupLogging:
    def test_returns_labwatch_logger(self, tmp_path):
        log_file = tmp_path / "labwatch.log"
        with patch("labwatch.logging_setup.log_path", return_value=log_file):
            # Clear any existing handlers from prior tests
            logger = logging.getLogger("labwatch")
            logger.handlers.clear()

            result = setup_logging()
            assert result.name == "labwatch"

            # Clean up
            for h in result.handlers[:]:
                h.close()
                result.removeHandler(h)

    def test_idempotent(self, tmp_path):
        """Calling setup_logging() twice should not add duplicate handlers."""
        log_file = tmp_path / "labwatch.log"
        with patch("labwatch.logging_setup.log_path", return_value=log_file):
            logger = logging.getLogger("labwatch")
            logger.handlers.clear()

            setup_logging()
            handler_count = len(logger.handlers)
            setup_logging()
            assert len(logger.handlers) == handler_count

            # Clean up
            for h in logger.handlers[:]:
                h.close()
                logger.removeHandler(h)

    def test_handler_max_bytes(self, tmp_path):
        """RotatingFileHandler should be configured to 512KB."""
        log_file = tmp_path / "labwatch.log"
        with patch("labwatch.logging_setup.log_path", return_value=log_file):
            logger = logging.getLogger("labwatch")
            logger.handlers.clear()

            setup_logging()

            rfh = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
            assert len(rfh) == 1
            assert rfh[0].maxBytes == 512 * 1024
            assert rfh[0].backupCount == 1

            # Clean up
            for h in logger.handlers[:]:
                h.close()
                logger.removeHandler(h)

    def test_creates_log_file(self, tmp_path):
        """Log file should be created after setup and a write."""
        log_file = tmp_path / "labwatch.log"
        with patch("labwatch.logging_setup.log_path", return_value=log_file):
            logger = logging.getLogger("labwatch")
            logger.handlers.clear()

            setup_logging()
            logger.info("test message")

            assert log_file.exists()

            # Clean up
            for h in logger.handlers[:]:
                h.close()
                logger.removeHandler(h)

    def test_log_format(self, tmp_path):
        """Log lines should contain the expected format elements."""
        log_file = tmp_path / "labwatch.log"
        with patch("labwatch.logging_setup.log_path", return_value=log_file):
            logger = logging.getLogger("labwatch")
            logger.handlers.clear()

            setup_logging()
            logger.info("check complete: 8 ok, 0 failed, worst=ok")

            for h in logger.handlers:
                h.flush()

            content = log_file.read_text()
            assert "INFO" in content
            assert "check complete: 8 ok, 0 failed, worst=ok" in content

            # Clean up
            for h in logger.handlers[:]:
                h.close()
                logger.removeHandler(h)
