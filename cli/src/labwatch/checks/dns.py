"""DNS resolution checks."""

import socket
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("dns")
class DnsCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        dns_cfg = self.config.get("checks", {}).get("dns", {})
        domains = dns_cfg.get("domains", [])

        if not domains:
            return []

        results = []
        for domain in domains:
            try:
                infos = socket.getaddrinfo(domain, None)
                ip = infos[0][4][0] if infos else "unknown"
                results.append(CheckResult(
                    name=f"dns:{domain}",
                    severity=Severity.OK,
                    message=f"Resolved to {ip}",
                ))
            except socket.gaierror as e:
                results.append(CheckResult(
                    name=f"dns:{domain}",
                    severity=Severity.CRITICAL,
                    message=f"Resolution failed: {e}",
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"dns:{domain}",
                    severity=Severity.UNKNOWN,
                    message=str(e),
                ))
        return results
