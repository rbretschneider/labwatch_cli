"""Rotating file logger for labwatch — keeps max ~1 MB on disk."""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _log_path() -> Path:
    """Return the log file path, next to the config/state files."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "labwatch" / "labwatch.log"


def setup_logging() -> logging.Logger:
    """Configure and return the ``labwatch`` logger.

    * 512 KB max per file, 1 backup = **1 MB total** on disk.
    * Idempotent: safe to call multiple times (checks for existing handlers).
    """
    logger = logging.getLogger("labwatch")

    # Avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_file = _log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        str(log_file),
        maxBytes=512 * 1024,  # 512 KB
        backupCount=1,
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    )

    logger.addHandler(handler)
    return logger
