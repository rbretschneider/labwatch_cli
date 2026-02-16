"""Home Assistant and Google Home integration checks."""

from typing import List

import requests

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("home_assistant")
class HomeAssistantCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        ha_cfg = self.config.get("checks", {}).get("home_assistant", {})
        url = ha_cfg.get("url", "http://localhost:8123").rstrip("/")
        external_url = ha_cfg.get("external_url", "").rstrip("/")
        token = ha_cfg.get("token", "")
        google_home = ha_cfg.get("google_home", True)

        results = []

        results.append(self._check_api(url))

        if external_url:
            results.append(self._check_external(external_url))

        if google_home:
            results.extend(self._check_google_apis())

        if token:
            results.extend(self._check_authenticated(url, token))

        return results

    def _check_api(self, url: str) -> CheckResult:
        try:
            resp = requests.get(f"{url}/api/", timeout=10)
            if resp.status_code < 400:
                return CheckResult(
                    name="ha:api",
                    severity=Severity.OK,
                    message=f"HA API responding (HTTP {resp.status_code})",
                )
            return CheckResult(
                name="ha:api",
                severity=Severity.CRITICAL,
                message=f"HA API returned HTTP {resp.status_code}",
            )
        except requests.ConnectionError:
            return CheckResult(
                name="ha:api",
                severity=Severity.CRITICAL,
                message="HA API unreachable (connection refused)",
            )
        except requests.Timeout:
            return CheckResult(
                name="ha:api",
                severity=Severity.CRITICAL,
                message="HA API timeout after 10s",
            )
        except Exception as e:
            return CheckResult(
                name="ha:api",
                severity=Severity.UNKNOWN,
                message=str(e),
            )

    def _check_external(self, external_url: str) -> CheckResult:
        try:
            resp = requests.get(external_url, timeout=15, allow_redirects=True)
            if resp.status_code < 400:
                return CheckResult(
                    name="ha:external",
                    severity=Severity.OK,
                    message=f"External URL reachable (HTTP {resp.status_code})",
                )
            return CheckResult(
                name="ha:external",
                severity=Severity.CRITICAL,
                message=f"External URL returned HTTP {resp.status_code}",
            )
        except requests.ConnectionError:
            return CheckResult(
                name="ha:external",
                severity=Severity.CRITICAL,
                message="External URL unreachable",
            )
        except requests.Timeout:
            return CheckResult(
                name="ha:external",
                severity=Severity.CRITICAL,
                message="External URL timeout after 15s",
            )
        except Exception as e:
            return CheckResult(
                name="ha:external",
                severity=Severity.UNKNOWN,
                message=str(e),
            )

    def _check_google_apis(self) -> List[CheckResult]:
        results = []
        apis = [
            ("ha:google_oauth", "https://oauth2.googleapis.com"),
            ("ha:google_homegraph", "https://homegraph.googleapis.com"),
        ]
        for name, url in apis:
            try:
                resp = requests.get(url, timeout=10)
                # Any response means the API is reachable
                results.append(CheckResult(
                    name=name,
                    severity=Severity.OK,
                    message=f"Reachable (HTTP {resp.status_code})",
                ))
            except requests.ConnectionError:
                results.append(CheckResult(
                    name=name,
                    severity=Severity.CRITICAL,
                    message="Unreachable (connection failed)",
                ))
            except requests.Timeout:
                results.append(CheckResult(
                    name=name,
                    severity=Severity.CRITICAL,
                    message="Timeout after 10s",
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=name,
                    severity=Severity.UNKNOWN,
                    message=str(e),
                ))
        return results

    def _check_authenticated(self, url: str, token: str) -> List[CheckResult]:
        results = []
        headers = {"Authorization": f"Bearer {token}"}

        # Check auth via /api/config
        try:
            resp = requests.get(f"{url}/api/config", headers=headers, timeout=10)
            if resp.status_code == 200:
                results.append(CheckResult(
                    name="ha:auth",
                    severity=Severity.OK,
                    message="Authenticated successfully",
                ))
            else:
                results.append(CheckResult(
                    name="ha:auth",
                    severity=Severity.WARNING,
                    message=f"Auth failed (HTTP {resp.status_code})",
                ))
                return results  # Skip further auth checks
        except Exception as e:
            results.append(CheckResult(
                name="ha:auth",
                severity=Severity.WARNING,
                message=f"Auth check failed: {e}",
            ))
            return results

        # Check for Google Assistant integration
        try:
            resp = requests.get(
                f"{url}/api/config/config_entries/entry",
                headers=headers, timeout=10,
            )
            if resp.status_code == 200:
                entries = resp.json()
                domains = [e.get("domain", "") for e in entries if isinstance(e, dict)]
                if "google_assistant" in domains or "google" in domains:
                    results.append(CheckResult(
                        name="ha:google_integration",
                        severity=Severity.OK,
                        message="Google integration found",
                    ))
                else:
                    results.append(CheckResult(
                        name="ha:google_integration",
                        severity=Severity.CRITICAL,
                        message="Google integration not found in config entries",
                    ))
            else:
                results.append(CheckResult(
                    name="ha:google_integration",
                    severity=Severity.WARNING,
                    message=f"Could not list config entries (HTTP {resp.status_code})",
                ))
        except Exception as e:
            results.append(CheckResult(
                name="ha:google_integration",
                severity=Severity.WARNING,
                message=f"Could not check integrations: {e}",
            ))

        return results
