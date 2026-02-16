"""Docker auto-discovery and HTTP endpoint suggestions."""

from typing import Dict, List, Optional

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
