"""Docker Compose update engine for labwatch."""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from labwatch.notifications import get_notifiers

# Compose file names to search for, in priority order
COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]

# Tags considered "rolling" (always pull latest)
ROLLING_TAGS = {"latest", "nightly", "edge", "dev", "main", "master"}

# Pattern for version-pinned tags like 15, 3.12, v1.2.3, 1.2.3-alpine
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*([._-].*)?$")


def _detect_compose_cmd() -> List[str]:
    """Return the docker compose command (v2 plugin first, v1 fallback)."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, check=True, timeout=10,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        subprocess.run(
            ["docker-compose", "version"],
            capture_output=True, check=True, timeout=10,
        )
        return ["docker-compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        raise RuntimeError("Neither 'docker compose' nor 'docker-compose' found")


def is_pinned_tag(image_ref: str) -> bool:
    """Determine if an image reference has a pinned (non-rolling) tag.

    Returns True for version tags and digests (should be skipped).
    Returns False for rolling tags or no tag (should be updated).
    """
    # Digest-pinned: image@sha256:...
    if "@sha256:" in image_ref:
        return True

    # Split off the tag
    # Handle registry/repo:tag format
    parts = image_ref.rsplit(":", 1)
    if len(parts) == 1:
        # No tag — defaults to :latest → rolling
        return False

    tag = parts[1]

    # Check if the part after : could be a port (registry:port/image)
    if "/" in tag:
        # e.g. registry:5000/image — no actual tag
        return False

    if tag in ROLLING_TAGS:
        return False

    if _VERSION_RE.match(tag):
        return True

    # Unknown tag — treat as rolling to be safe
    return False


def _find_compose_file(directory: Path) -> Optional[Path]:
    """Find the compose file in a directory."""
    for name in COMPOSE_FILES:
        path = directory / name
        if path.exists():
            return path
    return None


@dataclass
class UpdateResult:
    """Result of updating a single compose directory."""
    directory: str
    services_pulled: List[str] = field(default_factory=list)
    services_updated: List[str] = field(default_factory=list)
    services_skipped: List[str] = field(default_factory=list)
    error: Optional[str] = None


class ComposeUpdater:
    """Pulls latest images and restarts changed Docker Compose services."""

    def __init__(self, config: dict, force: bool = False, dry_run: bool = False):
        self.config = config
        self.force = force
        self.dry_run = dry_run
        self.compose_dirs: List[str] = (
            config.get("update", {}).get("compose_dirs", [])
        )
        self._compose_cmd = _detect_compose_cmd()

    def run(self) -> List[UpdateResult]:
        """Update all configured compose directories."""
        results = []
        for dir_path in self.compose_dirs:
            result = self._update_directory(Path(dir_path))
            results.append(result)
        return results

    def _update_directory(self, directory: Path) -> UpdateResult:
        """Pull images and restart services in a single compose directory."""
        result = UpdateResult(directory=str(directory))

        if not directory.is_dir():
            result.error = f"Directory does not exist: {directory}"
            return result

        compose_file = _find_compose_file(directory)
        if not compose_file:
            result.error = f"No compose file found in {directory}"
            return result

        # Parse images from compose file
        images = self._get_compose_images(compose_file)
        if not images:
            result.error = f"No services with images found in {compose_file}"
            return result

        # Determine which services to pull
        services_to_pull = []
        for service, image in images.items():
            if not self.force and is_pinned_tag(image):
                result.services_skipped.append(f"{service} ({image})")
            else:
                services_to_pull.append(service)
                result.services_pulled.append(service)

        if not services_to_pull:
            return result

        if self.dry_run:
            result.services_updated = list(services_to_pull)
            return result

        # Get image IDs before pull
        ids_before = self._get_image_ids(directory)

        # Pull images
        try:
            subprocess.run(
                [*self._compose_cmd, "pull", *services_to_pull],
                cwd=directory, capture_output=True, check=True, timeout=600,
            )
        except subprocess.CalledProcessError as e:
            result.error = f"Pull failed: {e.stderr.decode(errors='replace').strip()}"
            return result
        except subprocess.TimeoutExpired:
            result.error = "Pull timed out after 600 seconds"
            return result

        # Get image IDs after pull
        ids_after = self._get_image_ids(directory)

        # Determine which services actually changed
        changed = ids_before != ids_after
        if changed:
            result.services_updated = list(services_to_pull)
            try:
                subprocess.run(
                    [*self._compose_cmd, "up", "-d"],
                    cwd=directory, capture_output=True, check=True, timeout=300,
                )
            except subprocess.CalledProcessError as e:
                result.error = f"Restart failed: {e.stderr.decode(errors='replace').strip()}"
            except subprocess.TimeoutExpired:
                result.error = "Restart timed out after 300 seconds"

        return result

    def _get_compose_images(self, compose_file: Path) -> Dict[str, str]:
        """Parse a compose file and return {service_name: image} dict."""
        with open(compose_file, "r") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return {}

        services = data.get("services", {})
        if not isinstance(services, dict):
            return {}

        images = {}
        for name, svc in services.items():
            if isinstance(svc, dict) and "image" in svc:
                images[name] = svc["image"]
        return images

    def _get_image_ids(self, directory: Path) -> str:
        """Get current image IDs for a compose project (used for change detection)."""
        try:
            proc = subprocess.run(
                [*self._compose_cmd, "images", "-q"],
                cwd=directory, capture_output=True, timeout=30,
            )
            return proc.stdout.decode(errors="replace").strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return ""

    def notify(self, results: List[UpdateResult]) -> None:
        """Send a notification summarizing update results."""
        notifiers = get_notifiers(self.config)
        if not notifiers:
            return

        hostname = self.config.get("hostname", "unknown")
        lines = []
        any_updates = False

        for r in results:
            if r.error:
                lines.append(f"ERROR {r.directory}: {r.error}")
            elif r.services_updated:
                any_updates = True
                lines.append(
                    f"{r.directory}: updated {', '.join(r.services_updated)}"
                )

        if not lines:
            return

        title = f"[{hostname}] Docker update {'completed' if not any_updates else 'applied'}"
        message = "\n".join(lines)

        for notifier in notifiers:
            try:
                notifier.send(title, message)
            except Exception:
                pass
