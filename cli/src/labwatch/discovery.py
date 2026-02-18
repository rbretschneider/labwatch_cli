"""Auto-discovery for Docker containers and systemd services."""

import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# Well-known container images and their typical HTTP ports/paths
KNOWN_SERVICES: Dict[str, Dict] = {
    "homeassistant": {"port": 8123, "path": "/api/", "name": "Home Assistant"},
    "home-assistant": {"port": 8123, "path": "/api/", "name": "Home Assistant"},
    "plex": {"port": 32400, "path": "/identity", "name": "Plex"},
    "plexmediaserver": {"port": 32400, "path": "/identity", "name": "Plex"},
    "nginx": {"port": 80, "path": "/", "name": "Nginx"},
    "traefik": {"port": 8080, "path": "/api/overview", "name": "Traefik"},
    "grafana": {"port": 3000, "path": "/api/health", "name": "Grafana"},
    "portainer": {"port": 9000, "path": "/api/status", "name": "Portainer"},
    "jellyfin": {"port": 8096, "path": "/health", "name": "Jellyfin"},
    "sonarr": {"port": 8989, "path": "/ping", "name": "Sonarr"},
    "radarr": {"port": 7878, "path": "/ping", "name": "Radarr"},
    "pihole": {"port": 80, "path": "/admin/api.php", "name": "Pi-hole"},
    "adguardhome": {"port": 3000, "path": "/", "name": "AdGuard Home"},
    "nextcloud": {"port": 80, "path": "/status.php", "name": "Nextcloud"},
    "vaultwarden": {"port": 80, "path": "/alive", "name": "Vaultwarden"},
    "uptime-kuma": {"port": 3001, "path": "/", "name": "Uptime Kuma"},
}


def discover_compose_dirs() -> Optional[List[Tuple[str, str]]]:
    """Discover Docker Compose project directories from running containers.

    Reads the ``com.docker.compose.project.working_dir`` label that Docker
    Compose sets on every container it manages.

    Returns a deduplicated list of ``(project_name, working_dir)`` tuples
    sorted by project name, or *None* if Docker is unavailable.
    """
    try:
        import docker
        client = docker.from_env()
        client.ping()
    except Exception:
        return None

    seen: Dict[str, str] = {}
    for container in client.containers.list(all=True):
        labels = container.labels or {}
        working_dir = labels.get("com.docker.compose.project.working_dir")
        project = labels.get("com.docker.compose.project")
        if working_dir and project and project not in seen:
            seen[project] = working_dir

    return sorted(seen.items(), key=lambda x: x[0])


def discover_containers() -> Optional[List[Dict]]:
    """List all Docker containers. Returns None if Docker is unavailable."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
    except Exception:
        return None

    result = []
    for container in client.containers.list(all=True):
        image_tags = container.image.tags
        image = image_tags[0] if image_tags else str(container.image.id[:12])
        result.append({
            "name": container.name,
            "image": image,
            "status": container.status,
        })

    return result


def suggest_endpoints(containers: List[Dict]) -> List[Dict]:
    """Suggest HTTP endpoints based on container names/images."""
    suggestions = []
    seen = set()

    for c in containers:
        name_lower = c["name"].lower()
        image_lower = c["image"].lower().split("/")[-1].split(":")[0]

        for key, info in KNOWN_SERVICES.items():
            if key in name_lower or key in image_lower:
                if info["name"] not in seen:
                    seen.add(info["name"])
                    suggestions.append({
                        "name": info["name"],
                        "url": f"http://localhost:{info['port']}{info['path']}",
                        "timeout": 10,
                    })
                break

    return suggestions


# ---------------------------------------------------------------------------
# Systemd service discovery
# ---------------------------------------------------------------------------

# Known homelab service patterns: unit name substring -> friendly label.
# Used to highlight services a homelab user likely cares about.
KNOWN_SYSTEMD_SERVICES: Dict[str, str] = {
    # Printing
    "cups": "CUPS printing",
    "cupsd": "CUPS printing",
    # DNS / ad-blocking
    "pihole-FTL": "Pi-hole FTL",
    "lighttpd": "lighttpd (Pi-hole web)",
    "adguardhome": "AdGuard Home",
    "unbound": "Unbound DNS resolver",
    "dnsmasq": "dnsmasq DNS",
    # VPN / networking
    "wg-quick@": "WireGuard",
    "wireguard": "WireGuard",
    "tailscaled": "Tailscale",
    "openvpn": "OpenVPN",
    "zerotier": "ZeroTier",
    # Web / reverse proxy
    "nginx": "Nginx",
    "apache2": "Apache",
    "httpd": "Apache",
    "traefik": "Traefik",
    "caddy": "Caddy",
    "haproxy": "HAProxy",
    # Media
    "plexmediaserver": "Plex",
    "jellyfin": "Jellyfin",
    "emby": "Emby",
    "minidlna": "MiniDLNA",
    # Home automation
    "homeassistant": "Home Assistant",
    "home-assistant": "Home Assistant",
    "mosquitto": "Mosquitto MQTT",
    "zigbee2mqtt": "Zigbee2MQTT",
    # File sharing / sync
    "smbd": "Samba",
    "nmbd": "Samba NetBIOS",
    "nfs-server": "NFS server",
    "syncthing": "Syncthing",
    "nextcloud": "Nextcloud",
    # Containers / orchestration
    "docker": "Docker",
    "containerd": "containerd",
    "podman": "Podman",
    # Databases
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "influxdb": "InfluxDB",
    # Monitoring / logging
    "grafana-server": "Grafana",
    "prometheus": "Prometheus",
    "node_exporter": "Node Exporter",
    "loki": "Loki",
    # Download / media management
    "sonarr": "Sonarr",
    "radarr": "Radarr",
    "prowlarr": "Prowlarr",
    "lidarr": "Lidarr",
    "transmission": "Transmission",
    "qbittorrent": "qBittorrent",
    # Security / auth
    "vaultwarden": "Vaultwarden",
    "fail2ban": "Fail2ban",
    "crowdsec": "CrowdSec",
    # Core system (things users may still want to monitor)
    "sshd": "SSH",
    "ssh": "SSH",
    "cron": "Cron",
    "ufw": "UFW firewall",
    "firewalld": "firewalld",
}

# Unit prefixes/patterns that are OS plumbing, not user services.
_SYSTEMD_NOISE_PREFIXES = (
    "systemd-",
    "system-",
    "user@",
    "user-",
    "getty@",
    "serial-getty@",
    "console-getty",
    "init",
    "dbus",
    "polkit",
    "accounts-daemon",
    "networkd-",
    "resolved",
    "timesyncd",
    "logind",
    "journald",
    "udevd",
    "modprobe@",
    "kmod-",
    "lvm2-",
    "dm-event",
    "multipathd",
    "blk-availability",
    "snapd",
    "packagekit",
    "switcheroo-",
    "udisks2",
    "thermald",
    "power-profiles",
    "colord",
    "avahi-daemon",
    "wpa_supplicant",
    "ModemManager",
    "plymouth-",
)


def discover_systemd_units() -> Optional[List[Dict]]:
    """Discover running and enabled systemd service units.

    Returns a list of dicts with keys:
      - ``unit``: unit name (e.g. "cups.service")
      - ``state``: active/inactive/failed
      - ``label``: friendly name if recognized, else None

    Returns *None* if systemctl is not available.
    """
    if sys.platform == "win32":
        return None

    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all",
             "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None

    units: List[Dict] = []
    seen = set()

    for line in proc.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue

        unit_name = parts[0].strip()
        # systemctl can prefix with a bullet character on failed units
        if unit_name.startswith("\u25cf"):
            unit_name = parts[1].strip() if len(parts) > 4 else unit_name[1:]

        active_state = parts[2] if len(parts) > 2 else "unknown"

        # Skip noise
        base = unit_name.replace(".service", "")
        if any(base.startswith(p) or base == p.rstrip("-") for p in _SYSTEMD_NOISE_PREFIXES):
            continue

        if unit_name in seen:
            continue
        seen.add(unit_name)

        # Try to match a known service
        label = None
        for pattern, friendly in KNOWN_SYSTEMD_SERVICES.items():
            if pattern in base:
                label = friendly
                break

        units.append({
            "unit": unit_name,
            "state": active_state,
            "label": label,
        })

    # Sort: known/labeled services first, then alphabetical
    units.sort(key=lambda u: (u["label"] is None, u["unit"]))
    return units
