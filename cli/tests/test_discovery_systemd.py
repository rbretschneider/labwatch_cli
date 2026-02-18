"""Tests for systemd service discovery."""

from unittest.mock import patch, MagicMock

from labwatch.discovery import (
    discover_systemd_units,
    KNOWN_SYSTEMD_SERVICES,
    _SYSTEMD_NOISE_PREFIXES,
)


SAMPLE_SYSTEMCTL_OUTPUT = """\
  cups.service                       loaded active running CUPS Scheduler
  docker.service                     loaded active running Docker Application Container Engine
  grafana-server.service             loaded active running Grafana instance
  nginx.service                      loaded active running A high performance web server
  sshd.service                       loaded active running OpenBSD Secure Shell server
  wg-quick@wg0.service              loaded active running WireGuard via wg-quick(8) for wg0
  pihole-FTL.service                 loaded active running Pi-hole FTL DNS
"""

SAMPLE_WITH_NOISE = """\
  cups.service                       loaded active running CUPS Scheduler
  systemd-journald.service           loaded active running Journal Service
  systemd-logind.service             loaded active running Login Service
  user@1000.service                  loaded active running User Manager for UID 1000
  dbus.service                       loaded active running D-Bus System Message Bus
  nginx.service                      loaded active running A high performance web server
"""

SAMPLE_WITH_FAILED = """\
\u25cf nginx.service                      loaded failed failed A high performance web server
  docker.service                     loaded active running Docker Application Container Engine
"""


class TestDiscoverSystemdUnits:
    @patch("labwatch.discovery.sys")
    def test_returns_none_on_windows(self, mock_sys):
        mock_sys.platform = "win32"
        assert discover_systemd_units() is None

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run", side_effect=FileNotFoundError)
    def test_returns_none_when_systemctl_missing(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        assert discover_systemd_units() is None

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_returns_none_on_nonzero_exit(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert discover_systemd_units() is None

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_discovers_known_services(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_SYSTEMCTL_OUTPUT)

        units = discover_systemd_units()
        assert units is not None

        labels = {u["label"] for u in units if u["label"]}
        assert "CUPS printing" in labels
        assert "Docker" in labels
        assert "Grafana" in labels
        assert "Nginx" in labels
        assert "SSH" in labels

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_known_services_sorted_first(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_SYSTEMCTL_OUTPUT)

        units = discover_systemd_units()
        labeled = [u for u in units if u["label"]]
        unlabeled = [u for u in units if not u["label"]]

        # All labeled units should come before unlabeled
        if labeled and unlabeled:
            labeled_indices = [units.index(u) for u in labeled]
            unlabeled_indices = [units.index(u) for u in unlabeled]
            assert max(labeled_indices) < min(unlabeled_indices)

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_noise_filtered_out(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_WITH_NOISE)

        units = discover_systemd_units()
        unit_names = [u["unit"] for u in units]

        assert "systemd-journald.service" not in unit_names
        assert "systemd-logind.service" not in unit_names
        assert "user@1000.service" not in unit_names
        assert "dbus.service" not in unit_names
        # cups and nginx should survive filtering
        assert "cups.service" in unit_names
        assert "nginx.service" in unit_names

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_failed_unit_parsed(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_WITH_FAILED)

        units = discover_systemd_units()
        docker_units = [u for u in units if "docker" in u["unit"]]
        assert len(docker_units) == 1
        assert docker_units[0]["state"] == "active"

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_empty_output(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        units = discover_systemd_units()
        assert units == []

    @patch("labwatch.discovery.sys")
    @patch("labwatch.discovery.subprocess.run")
    def test_state_captured(self, mock_run, mock_sys):
        mock_sys.platform = "linux"
        mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_SYSTEMCTL_OUTPUT)

        units = discover_systemd_units()
        for u in units:
            assert u["state"] in ("active", "inactive", "failed", "unknown")


class TestKnownServicePatterns:
    """Verify key homelab services are recognized."""

    def test_cups_recognized(self):
        assert "cups" in KNOWN_SYSTEMD_SERVICES

    def test_pihole_recognized(self):
        assert "pihole-FTL" in KNOWN_SYSTEMD_SERVICES

    def test_wireguard_recognized(self):
        assert "wg-quick@" in KNOWN_SYSTEMD_SERVICES

    def test_docker_recognized(self):
        assert "docker" in KNOWN_SYSTEMD_SERVICES

    def test_sshd_recognized(self):
        assert "sshd" in KNOWN_SYSTEMD_SERVICES

    def test_grafana_recognized(self):
        assert "grafana-server" in KNOWN_SYSTEMD_SERVICES

    def test_tailscale_recognized(self):
        assert "tailscaled" in KNOWN_SYSTEMD_SERVICES


class TestNoiseFiltering:
    """Verify that OS plumbing prefixes are excluded."""

    def test_systemd_prefix_is_noise(self):
        assert any(p.startswith("systemd-") for p in _SYSTEMD_NOISE_PREFIXES)

    def test_user_prefix_is_noise(self):
        assert "user@" in _SYSTEMD_NOISE_PREFIXES

    def test_dbus_is_noise(self):
        assert "dbus" in _SYSTEMD_NOISE_PREFIXES

    def test_snapd_is_noise(self):
        assert "snapd" in _SYSTEMD_NOISE_PREFIXES
