"""Tests for the `labwatch summarize` command and _build_summary helper."""

import copy

from click.testing import CliRunner

from labwatch.cli import cli, _build_summary


class TestBuildSummaryHostname:
    def test_hostname_appears_first(self, full_cfg):
        lines = _build_summary(full_cfg)
        assert lines[0] == "Server: test-server"

    def test_default_hostname(self):
        lines = _build_summary({"notifications": {}, "checks": {}})
        assert lines[0] == "Server: unknown"


class TestBuildSummaryNotifications:
    def test_ntfy_enabled(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "Notifications: ntfy enabled" in text
        assert "https://ntfy.example.com/test_alerts" in text
        assert "CRITICAL -> urgent" in text
        assert "severity >= warning" in text

    def test_ntfy_disabled(self, default_cfg):
        default_cfg["notifications"]["ntfy"]["enabled"] = False
        text = "\n".join(_build_summary(default_cfg))
        assert "Notifications: disabled" in text

    def test_min_severity_critical(self, full_cfg):
        full_cfg["notifications"]["min_severity"] = "critical"
        text = "\n".join(_build_summary(full_cfg))
        assert "severity >= critical" in text


class TestBuildSummarySystemCheck:
    def test_system_thresholds(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "disk warn 75%/crit 90%" in text
        assert "mem warn 70%/crit 95%" in text
        assert "CPU load multiplier 3x" in text

    def test_system_disabled(self, default_cfg):
        default_cfg["checks"]["system"]["enabled"] = False
        text = "\n".join(_build_summary(default_cfg))
        assert "System:" not in text
        assert "System" in text.split("Disabled:")[1]


class TestBuildSummaryDockerCheck:
    def test_specific_containers(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "watching containers: plex, grafana" in text
        assert "alerting on stopped containers" in text

    def test_all_containers(self, full_cfg):
        full_cfg["checks"]["docker"]["containers"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "watching all containers" in text

    def test_watch_stopped_off(self, full_cfg):
        full_cfg["checks"]["docker"]["watch_stopped"] = False
        text = "\n".join(_build_summary(full_cfg))
        assert "alerting on stopped" not in text


class TestBuildSummaryHTTPCheck:
    def test_endpoints_listed(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "HA -> http://localhost:8123" in text
        assert "Plex -> http://localhost:32400/identity" in text

    def test_no_endpoints(self, full_cfg):
        full_cfg["checks"]["http"]["endpoints"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no endpoints configured)" in text


class TestBuildSummaryNginxCheck:
    def test_docker_mode(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "via Docker container 'nginx-proxy'" in text
        assert "endpoint: https://example.com" in text

    def test_host_mode(self, full_cfg):
        full_cfg["checks"]["nginx"]["container"] = ""
        text = "\n".join(_build_summary(full_cfg))
        assert "via host systemd/process" in text


class TestBuildSummaryDNSCheck:
    def test_domains_listed(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "resolving: google.com" in text
        assert "resolving: github.com" in text

    def test_no_domains(self, full_cfg):
        full_cfg["checks"]["dns"]["domains"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no domains configured)" in text


class TestBuildSummaryPingCheck:
    def test_hosts_and_timeout(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "pinging: 8.8.8.8" in text
        assert "pinging: 1.1.1.1" in text
        assert "timeout: 3s" in text


class TestBuildSummaryHomeAssistant:
    def test_ha_full(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "URL: http://ha.local:8123" in text
        assert "external URL: https://ha.example.com" in text
        assert "authenticated (token set)" in text
        assert "Google Home connectivity check enabled" in text

    def test_ha_no_token(self, full_cfg):
        full_cfg["checks"]["home_assistant"]["token"] = ""
        text = "\n".join(_build_summary(full_cfg))
        assert "unauthenticated (no token)" in text

    def test_ha_no_external_url(self, full_cfg):
        full_cfg["checks"]["home_assistant"]["external_url"] = ""
        text = "\n".join(_build_summary(full_cfg))
        assert "external URL" not in text


class TestBuildSummarySystemdCheck:
    def test_units_with_severity(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "nginx (critical)" in text
        assert "docker (critical)" in text
        assert "caddy (warning)" in text

    def test_no_units(self, full_cfg):
        full_cfg["checks"]["systemd"]["units"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no units configured)" in text


class TestBuildSummaryProcessCheck:
    def test_process_names(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "redis-server" in text
        assert "Processes:" in text

    def test_no_process_names(self, full_cfg):
        full_cfg["checks"]["process"]["names"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no process names configured)" in text


class TestBuildSummaryCommandCheck:
    def test_commands_with_extras(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "nginx config: `nginx -t`" in text
        assert "expect 'successful' in output" in text
        assert "severity: warning" in text
        assert "backup ran today: `find /backups" in text

    def test_no_commands(self, full_cfg):
        full_cfg["checks"]["command"]["commands"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no commands configured)" in text

    def test_non_default_exit_code(self, full_cfg):
        full_cfg["checks"]["command"]["commands"] = [
            {"name": "test", "command": "false", "expect_exit": 1},
        ]
        text = "\n".join(_build_summary(full_cfg))
        assert "expect exit 1" in text


class TestBuildSummaryNetworkCheck:
    def test_interfaces_listed(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "Network interfaces:" in text
        assert "tun0 (critical)" in text
        assert "wg0 (warning)" in text

    def test_no_interfaces(self, full_cfg):
        full_cfg["checks"]["network"]["interfaces"] = []
        text = "\n".join(_build_summary(full_cfg))
        assert "(no interfaces configured)" in text


class TestBuildSummaryCheckCounts:
    def test_all_enabled_count(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "11 check groups enabled" in text

    def test_nothing_enabled(self):
        cfg = {
            "hostname": "bare",
            "notifications": {},
            "checks": {
                "system": {"enabled": False},
                "docker": {"enabled": False},
                "http": {"enabled": False},
            },
        }
        text = "\n".join(_build_summary(cfg))
        assert "No checks are currently enabled." in text


class TestBuildSummaryDisabledList:
    def test_disabled_list(self, default_cfg):
        # Default config has system, docker, http enabled; rest disabled
        text = "\n".join(_build_summary(default_cfg))
        disabled_section = text.split("Disabled: ")[1]
        for name in ["Nginx", "DNS", "Ping", "Network", "Home Assistant", "Systemd", "Process", "Command"]:
            assert name in disabled_section

    def test_all_enabled_no_disabled(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "Disabled:" not in text


class TestBuildSummaryAutoUpdates:
    def test_compose_dirs_listed(self, full_cfg):
        text = "\n".join(_build_summary(full_cfg))
        assert "Docker Compose auto-update directories:" in text
        assert "/opt/stacks/media" in text
        assert "/opt/stacks/monitoring" in text

    def test_no_compose_dirs(self, default_cfg):
        text = "\n".join(_build_summary(default_cfg))
        assert "Docker Compose auto-update" not in text


class TestSummarizeCliCommand:
    def test_cli_invocation(self, tmp_path):
        """summarize command runs and produces output via Click runner."""
        import yaml
        cfg = {
            "hostname": "cli-test",
            "notifications": {"ntfy": {"enabled": False}},
            "checks": {"system": {"enabled": True, "thresholds": {}}},
        }
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump(cfg))

        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(cfg_file), "summarize"])
        assert result.exit_code == 0
        assert "Server: cli-test" in result.output
        assert "System:" in result.output
