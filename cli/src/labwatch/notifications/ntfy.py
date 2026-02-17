"""ntfy push notification backend."""

import requests

from labwatch.notifications import BaseNotifier, register


@register("ntfy")
class NtfyNotifier(BaseNotifier):

    @property
    def name(self) -> str:
        return "ntfy"

    SEVERITY_PRIORITY = {
        "critical": "high",
        "warning": "default",
        "ok": "low",
        "unknown": "low",
        "default": "low",
    }

    def send(self, title: str, message: str, severity: str = "default") -> None:
        server = self.config.get("server", "https://ntfy.sh").rstrip("/")
        topic = self.config.get("topic", "homelab_alerts")
        url = f"{server}/{topic}"
        priority = self.SEVERITY_PRIORITY.get(severity.lower(), "default")

        resp = requests.post(
            url,
            data=message.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": priority,
            },
            timeout=10,
        )
        resp.raise_for_status()
