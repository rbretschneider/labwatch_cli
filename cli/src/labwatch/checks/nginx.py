"""Nginx health checks: service status, config validation, endpoint reachability."""

import subprocess
from typing import List

import requests

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("nginx")
class NginxCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        nginx_cfg = self.config.get("checks", {}).get("nginx", {})
        container = nginx_cfg.get("container", "")
        endpoints = nginx_cfg.get("endpoints", [])
        config_test = nginx_cfg.get("config_test", True)

        results = []
        results.append(self._check_service(container))
        if config_test:
            results.append(self._check_config(container))
        results.extend(self._check_endpoints(endpoints))
        return results

    def _check_service(self, container: str) -> CheckResult:
        if container:
            return self._check_service_docker(container)
        return self._check_service_host()

    def _check_service_docker(self, container: str) -> CheckResult:
        try:
            import docker
            client = docker.from_env()
            ctr = client.containers.get(container)
            if ctr.status == "running":
                return CheckResult(
                    name="nginx:service",
                    severity=Severity.OK,
                    message=f"Container '{container}' is running",
                )
            return CheckResult(
                name="nginx:service",
                severity=Severity.CRITICAL,
                message=f"Container '{container}' status: {ctr.status}",
            )
        except ImportError:
            return CheckResult(
                name="nginx:service",
                severity=Severity.UNKNOWN,
                message="docker package not installed",
            )
        except Exception as e:
            return CheckResult(
                name="nginx:service",
                severity=Severity.CRITICAL,
                message=f"Container '{container}' not found: {e}",
            )

    def _check_service_host(self) -> CheckResult:
        # Try systemctl first, fall back to pgrep
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "nginx"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip() == "active":
                return CheckResult(
                    name="nginx:service",
                    severity=Severity.OK,
                    message="nginx service is active (systemd)",
                )
        except FileNotFoundError:
            pass
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["pgrep", "-x", "nginx"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return CheckResult(
                    name="nginx:service",
                    severity=Severity.OK,
                    message="nginx process is running",
                )
        except FileNotFoundError:
            return CheckResult(
                name="nginx:service",
                severity=Severity.UNKNOWN,
                message="Cannot check nginx: systemctl and pgrep not available",
            )
        except Exception:
            pass

        return CheckResult(
            name="nginx:service",
            severity=Severity.CRITICAL,
            message="nginx is not running",
        )

    def _check_config(self, container: str) -> CheckResult:
        try:
            if container:
                import docker
                client = docker.from_env()
                ctr = client.containers.get(container)
                exit_code, output = ctr.exec_run("nginx -t")
                raw = output.decode(errors="replace")
            else:
                # nginx -t often needs root to access /etc/nginx and its
                # temp/log directories.  Try sudo first, fall back to plain.
                for cmd in (["sudo", "-n", "nginx", "-t"], ["nginx", "-t"]):
                    try:
                        result = subprocess.run(
                            cmd,
                            capture_output=True, text=True, timeout=10,
                        )
                        exit_code = result.returncode
                        raw = result.stderr + result.stdout
                        # If sudo isn't available or denied, the exit code
                        # will be non-zero and raw will mention sudo/password;
                        # in that case try the next command.
                        if exit_code == 0 or "successful" in raw.lower():
                            break
                        if "sudo" in raw.lower() and "password" in raw.lower():
                            continue
                        break  # genuine nginx failure, don't retry
                    except FileNotFoundError:
                        continue  # sudo not installed, try plain nginx

            if exit_code == 0 or "successful" in raw.lower():
                return CheckResult(
                    name="nginx:config",
                    severity=Severity.OK,
                    message="Configuration test passed",
                )
            return CheckResult(
                name="nginx:config",
                severity=Severity.WARNING,
                message=f"Configuration test failed: {raw.strip()[:200]}",
            )
        except Exception as e:
            return CheckResult(
                name="nginx:config",
                severity=Severity.WARNING,
                message=f"Could not test config: {e}",
            )

    def _check_endpoints(self, endpoints: list) -> List[CheckResult]:
        results = []
        for url in endpoints:
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True)
                if resp.status_code < 400:
                    results.append(CheckResult(
                        name=f"nginx:endpoint:{url}",
                        severity=Severity.OK,
                        message=f"HTTP {resp.status_code} ({resp.elapsed.total_seconds():.2f}s)",
                    ))
                else:
                    results.append(CheckResult(
                        name=f"nginx:endpoint:{url}",
                        severity=Severity.CRITICAL,
                        message=f"HTTP {resp.status_code}",
                    ))
            except requests.ConnectionError:
                results.append(CheckResult(
                    name=f"nginx:endpoint:{url}",
                    severity=Severity.CRITICAL,
                    message="Connection refused",
                ))
            except requests.Timeout:
                results.append(CheckResult(
                    name=f"nginx:endpoint:{url}",
                    severity=Severity.CRITICAL,
                    message="Timeout after 10s",
                ))
            except Exception as e:
                results.append(CheckResult(
                    name=f"nginx:endpoint:{url}",
                    severity=Severity.UNKNOWN,
                    message=str(e),
                ))
        return results
