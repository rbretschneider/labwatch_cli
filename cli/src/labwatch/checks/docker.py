"""Docker daemon health and container status checks."""

from typing import List

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("docker")
class DockerCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        try:
            import docker
        except ImportError:
            return [CheckResult(
                name="docker",
                severity=Severity.UNKNOWN,
                message="docker package not installed",
            )]

        try:
            client = docker.from_env()
            client.ping()
        except Exception as e:
            return [CheckResult(
                name="docker:daemon",
                severity=Severity.CRITICAL,
                message=f"Docker daemon unreachable: {e}",
            )]

        results = [CheckResult(
            name="docker:daemon",
            severity=Severity.OK,
            message="Docker daemon is running",
        )]

        docker_cfg = self.config.get("checks", {}).get("docker", {})
        watch_stopped = docker_cfg.get("watch_stopped", True)
        filter_names = docker_cfg.get("containers", [])

        try:
            containers = client.containers.list(all=True)
        except Exception as e:
            results.append(CheckResult(
                name="docker:list",
                severity=Severity.UNKNOWN,
                message=f"Failed to list containers: {e}",
            ))
            return results

        for container in containers:
            name = container.name
            if filter_names and name not in filter_names:
                continue

            status = container.status  # running, exited, paused, etc.

            if status == "running":
                sev = Severity.OK
            elif status in ("paused", "restarting"):
                sev = Severity.WARNING
            else:
                sev = Severity.CRITICAL if watch_stopped else Severity.WARNING

            results.append(CheckResult(
                name=f"docker:{name}",
                severity=sev,
                message=status,
            ))

        return results
