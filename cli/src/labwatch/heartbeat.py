"""Dead man's switch: ping an external monitoring URL after each run."""

import logging

import requests

logger = logging.getLogger("labwatch")


def ping_heartbeat(config: dict, has_failures: bool = False) -> None:
    """HTTP GET a heartbeat URL (e.g. Healthchecks.io) after a check run.

    * Reads ``notifications.heartbeat_url`` from *config*.
    * Appends ``/fail`` when *has_failures* is True (Healthchecks.io convention).
    * 10 s timeout; swallows **all** exceptions so monitoring never crashes.
    """
    url = config.get("notifications", {}).get("heartbeat_url", "")
    if not url:
        return

    try:
        if has_failures:
            url = url.rstrip("/") + "/fail"
        requests.get(url, timeout=10)
        logger.info("heartbeat pinged")
    except Exception:
        logger.warning("heartbeat ping failed")
