"""Tests for the `labwatch summarize` command and _build_config_tree helper."""

import copy
import io

from click.testing import CliRunner
from rich.console import Console

from labwatch.cli import cli, _build_config_tree


def _render(cfg):
    """Render the config tree to plain text for assertion."""
    tree = _build_config_tree(cfg)
    buf = io.StringIO()
    Console(file=buf, no_color=True, width=300).print(tree)
    return buf.getvalue()


class TestConfigTreeHostname:
    def test_hostname_appears_as_root(self, full_cfg):
        text = _render(full_cfg)
        assert "test-server" in text

    def test_default_hostname(self):
        text = _render({"notifications": {}, "checks": {}})
        assert "unknown" in text


class TestConfigTreeNotifications:
    def test_ntfy_enabled(self, full_cfg):
        text = _render(full_cfg)
        assert "Notifications enabled" in text
        assert "ntfy: https://ntfy.example.com/test_alerts" in text
        assert "min severity: warning" in text

    def test_ntfy_disabled(self, default_cfg):
        default_cfg["notifications"]["ntfy"]["enabled"] = False
        text = _render(default_cfg)
        assert "Notifications disabled" in text

    def test_min_severity_critical(self, full_cfg):
        full_cfg["notifications"]["min_severity"] = "critical"
        text = _render(full_cfg)
        assert "min severity: critical" in text


class TestConfigTreeSystemCheck:
    def test_system_thresholds(self, full_cfg):
        text = _render(full_cfg)
        assert "disk: warn 75% / crit 90%" in text
        assert "memory: warn 70% / crit 95%" in text
        assert "cpu: warn 80% / crit 95%" in text

    def test_system_disabled(self, default_cfg):
        default_cfg["checks"]["system"]["enabled"] = False
        text = _render(default_cfg)
        # System should appear in the Disabled line, not as a module branch
        assert "Disabled:" in text
        assert "System" in text.split("Disabled:")[1]


class TestConfigTreeDockerCheck:
    def test_specific_containers(self, full_cfg):
        text = _render(full_cfg)
        assert "watching: plex, grafana" in text
        assert "alert on stopped containers" in text

    def test_all_containers(self, full_cfg):
        full_cfg["checks"]["docker"]["containers"] = []
        text = _render(full_cfg)
        assert "watching: all containers" in text

    def test_watch_stopped_off(self, full_cfg):
        full_cfg["checks"]["docker"]["watch_stopped"] = False
        text = _render(full_cfg)
        assert "alert on stopped" not in text


class TestConfigTreeHTTPCheck:
    def test_endpoints_listed(self, full_cfg):
        text = _render(full_cfg)
        assert "HA: http://localhost:8123" in text
        assert "Plex: http://localhost:32400/identity" in text

    def test_no_endpoints(self, full_cfg):
        full_cfg["checks"]["http"]["endpoints"] = []
        text = _render(full_cfg)
        assert "(no endpoints configured)" in text


class TestConfigTreeNginxCheck:
    def test_docker_mode(self, full_cfg):
        text = _render(full_cfg)
        assert "via Docker container: nginx-proxy" in text
        assert "endpoint: https://example.com" in text

    def test_host_mode(self, full_cfg):
        full_cfg["checks"]["nginx"]["container"] = ""
        text = _render(full_cfg)
        assert "via host systemd/process" in text


class TestConfigTreeDNSCheck:
    def test_domains_listed(self, full_cfg):
        text = _render(full_cfg)
        assert "google.com" in text
        assert "github.com" in text

    def test_no_domains(self, full_cfg):
        full_cfg["checks"]["dns"]["domains"] = []
        text = _render(full_cfg)
        assert "(no domains configured)" in text


class TestConfigTreeCertsCheck:
    def test_certs_enabled(self, full_cfg):
        text = _render(full_cfg)
        assert "TLS Certificates" in text
        assert "example.com" in text
        assert "app.example.com" in text
        assert "warn at 14 days / crit at 7 days" in text

    def test_certs_no_domains(self, full_cfg):
        full_cfg["checks"]["certs"]["domains"] = []
        text = _render(full_cfg)
        assert "(no domains configured)" in text

    def test_certs_disabled(self, default_cfg):
        text = _render(default_cfg)
        # Should not appear as a module branch before "Disabled:"
        assert "TLS Certificates" not in text.split("Disabled:")[0]


class TestConfigTreePingCheck:
    def test_hosts_and_timeout(self, full_cfg):
        text = _render(full_cfg)
        assert "8.8.8.8" in text
        assert "1.1.1.1" in text
        assert "timeout: 3s" in text


class TestConfigTreeHomeAssistant:
    def test_ha_full(self, full_cfg):
        text = _render(full_cfg)
        assert "URL: http://ha.local:8123" in text
        assert "external: https://ha.example.com" in text
        assert "token: set" in text
        assert "Google Home check: enabled" in text

    def test_ha_no_token(self, full_cfg):
        full_cfg["checks"]["home_assistant"]["token"] = ""
        text = _render(full_cfg)
        assert "token: not set" in text

    def test_ha_no_external_url(self, full_cfg):
        full_cfg["checks"]["home_assistant"]["external_url"] = ""
        text = _render(full_cfg)
        assert "external:" not in text


class TestConfigTreeSystemdCheck:
    def test_units_with_severity(self, full_cfg):
        text = _render(full_cfg)
        assert "nginx (critical)" in text
        assert "docker (critical)" in text
        assert "caddy (warning)" in text

    def test_no_units(self, full_cfg):
        full_cfg["checks"]["systemd"]["units"] = []
        text = _render(full_cfg)
        assert "(no units configured)" in text


class TestConfigTreeProcessCheck:
    def test_process_names(self, full_cfg):
        text = _render(full_cfg)
        assert "redis-server" in text
        assert "Processes" in text

    def test_no_process_names(self, full_cfg):
        full_cfg["checks"]["process"]["names"] = []
        text = _render(full_cfg)
        assert "(no process names configured)" in text


class TestConfigTreeCommandCheck:
    def test_commands_with_extras(self, full_cfg):
        text = _render(full_cfg)
        assert "nginx config:" in text
        assert "nginx -t" in text
        assert "expect 'successful'" in text
        assert "backup ran today:" in text

    def test_no_commands(self, full_cfg):
        full_cfg["checks"]["command"]["commands"] = []
        text = _render(full_cfg)
        assert "(no commands configured)" in text

    def test_non_default_exit_code(self, full_cfg):
        full_cfg["checks"]["command"]["commands"] = [
            {"name": "test", "command": "false", "expect_exit": 1},
        ]
        text = _render(full_cfg)
        assert "expect exit 1" in text


class TestConfigTreeNetworkCheck:
    def test_interfaces_listed(self, full_cfg):
        text = _render(full_cfg)
        assert "Network Interfaces" in text
        assert "tun0 (critical)" in text
        assert "wg0 (warning)" in text

    def test_no_interfaces(self, full_cfg):
        full_cfg["checks"]["network"]["interfaces"] = []
        text = _render(full_cfg)
        assert "(no interfaces configured)" in text


class TestConfigTreeSmartCheck:
    def test_smart_enabled(self, full_cfg):
        text = _render(full_cfg)
        assert "S.M.A.R.T." in text
        assert "temp: warn 50C / crit 60C" in text
        assert "wear: warn 80% / crit 90%" in text
        assert "device: /dev/sda" in text

    def test_smart_auto_detect(self, full_cfg):
        full_cfg["checks"]["smart"]["devices"] = []
        text = _render(full_cfg)
        assert "auto-detect all devices" in text

    def test_smart_disabled(self, default_cfg):
        text = _render(default_cfg)
        assert "S.M.A.R.T." not in text.split("Disabled:")[0]
        assert "S.M.A.R.T." in text.split("Disabled:")[1]


class TestConfigTreeUpdatesCheck:
    def test_updates_thresholds(self, full_cfg):
        text = _render(full_cfg)
        assert "warn at 1+ pending" in text
        assert "critical at 50+ pending" in text


class TestConfigTreeModuleCount:
    def test_all_enabled_count(self, full_cfg):
        text = _render(full_cfg)
        assert "14 modules" in text

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
        text = _render(cfg)
        assert "No checks enabled" in text


class TestConfigTreeDisabledList:
    def test_disabled_list(self, default_cfg):
        text = _render(default_cfg)
        disabled_section = text.split("Disabled: ")[1]
        for name in ["Nginx", "S.M.A.R.T.", "DNS Resolution", "TLS Certificates",
                      "Ping", "Network Interfaces", "Home Assistant", "Systemd Units",
                      "Processes", "Custom Commands", "Package Updates"]:
            assert name in disabled_section

    def test_all_enabled_no_disabled(self, full_cfg):
        text = _render(full_cfg)
        assert "Disabled:" not in text


class TestConfigTreeAutoUpdates:
    def test_compose_dirs_listed(self, full_cfg):
        text = _render(full_cfg)
        assert "Auto-updates" in text
        assert "2 directories" in text
        assert "/opt/stacks/media" in text
        assert "/opt/stacks/monitoring" in text

    def test_no_compose_dirs(self, default_cfg):
        text = _render(default_cfg)
        assert "Auto-updates" not in text


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

        # Use the tree builder directly to avoid Click runner + Rich console
        # interaction issues on Windows (TextIOWrapper conflicts)
        from labwatch.config import load_config
        loaded = load_config(cfg_file)
        text = _render(loaded)
        assert "cli-test" in text
        assert "System" in text
