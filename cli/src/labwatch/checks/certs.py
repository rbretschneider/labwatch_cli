"""TLS certificate expiry checks."""

import socket
import ssl
from datetime import datetime, timezone
from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("certs")
class CertsCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        certs_cfg = self.config.get("checks", {}).get("certs", {})
        domains = certs_cfg.get("domains", [])
        warn_days = certs_cfg.get("warn_days", 14)
        critical_days = certs_cfg.get("critical_days", 7)

        if not domains:
            return []

        results = []
        for domain in domains:
            results.append(self._check_domain(domain, warn_days, critical_days))
        return results

    def _check_domain(
        self, domain: str, warn_days: int, critical_days: int
    ) -> CheckResult:
        name = f"certs:{domain}"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()

            if not cert:
                return CheckResult(
                    name=name,
                    severity=Severity.UNKNOWN,
                    message="No certificate returned",
                )

            not_after_str = cert["notAfter"]
            # OpenSSL format: 'Mar 15 12:00:00 2025 GMT'
            not_after = datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days

            if days_remaining < 0:
                return CheckResult(
                    name=name,
                    severity=Severity.CRITICAL,
                    message=f"Certificate expired {-days_remaining} day(s) ago",
                )
            if days_remaining <= critical_days:
                return CheckResult(
                    name=name,
                    severity=Severity.CRITICAL,
                    message=f"Certificate expires in {days_remaining} day(s)",
                )
            if days_remaining <= warn_days:
                return CheckResult(
                    name=name,
                    severity=Severity.WARNING,
                    message=f"Certificate expires in {days_remaining} day(s)",
                )
            return CheckResult(
                name=name,
                severity=Severity.OK,
                message=f"Certificate valid for {days_remaining} day(s)",
            )

        except (socket.timeout, TimeoutError):
            return CheckResult(
                name=name,
                severity=Severity.CRITICAL,
                message="Connection timed out",
            )
        except ssl.SSLCertVerificationError as e:
            return CheckResult(
                name=name,
                severity=Severity.CRITICAL,
                message=f"Certificate verification failed: {e}",
            )
        except (ConnectionRefusedError, OSError) as e:
            return CheckResult(
                name=name,
                severity=Severity.CRITICAL,
                message=f"Connection failed: {e}",
            )
        except Exception as e:
            return CheckResult(
                name=name,
                severity=Severity.UNKNOWN,
                message=str(e),
            )
