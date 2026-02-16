"""Generic HTTP endpoint checker."""

from typing import List

import requests

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("http")
class HttpCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        http_cfg = self.config.get("checks", {}).get("http", {})
        endpoints = http_cfg.get("endpoints", [])

        if not endpoints:
            return []

        results = []
        for ep in endpoints:
            name = ep.get("name", ep.get("url", "unknown"))
            url = ep.get("url", "")
            timeout = ep.get("timeout", 10)
            expected_status = ep.get("expected_status", None)

            if not url:
                results.append(CheckResult(
                    name=f"http:{name}",
                    severity=Severity.UNKNOWN,
                    message="No URL configured",
                ))
                continue

            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)

                if expected_status and resp.status_code != expected_status:
                    results.append(CheckResult(
                        name=f"http:{name}",
                        severity=Severity.CRITICAL,
                        message=f"HTTP {resp.status_code} (expected {expected_status})",
                    ))
                elif resp.status_code < 400:
                    results.append(CheckResult(
                        name=f"http:{name}",
                        severity=Severity.OK,
                        message=f"HTTP {resp.status_code} ({resp.elapsed.total_seconds():.2f}s)",
                    ))
                else:
                    results.append(CheckResult(
                        name=f"http:{name}",
                        severity=Severity.CRITICAL,
                        message=f"HTTP {resp.status_code}",
                    ))
            except requests.ConnectionError:
                results.append(CheckResult(
                    name=f"http:{name}",
                    severity=Severity.CRITICAL,
                    message="Connection refused",
                ))
            except requests.Timeout:
                results.append(CheckResult(
                    name=f"http:{name}",
                    severity=Severity.CRITICAL,
                    message=f"Timeout after {timeout}s",
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"http:{name}",
                    severity=Severity.UNKNOWN,
                    message=str(e),
                ))

        return results
