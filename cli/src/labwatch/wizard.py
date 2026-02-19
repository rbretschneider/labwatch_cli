"""Interactive setup wizard for labwatch."""

import platform
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import click

from labwatch.config import DEFAULT_CONFIG, default_config_path, load_config, save_config, deep_merge
from labwatch.discovery import (
    discover_compose_dirs, discover_containers, discover_systemd_units,
    suggest_endpoints,
)

# Detailed descriptions shown before each check's enable prompt.  These are
# written for someone who may not know what each subsystem is or why they'd
# want to monitor it.
CHECK_DESCRIPTIONS = {
    "system": (
        "Checks disk space on every mounted partition, RAM usage, and CPU\n"
        "  load. You set warning and critical thresholds (e.g. warn at 80%,\n"
        "  critical at 90%). If any resource crosses a threshold, you get\n"
        "  an alert with the exact usage and how much headroom is left."
    ),
    "docker": (
        "If you run any services in Docker containers (Plex, Grafana,\n"
        "  Pi-hole, etc.), this module keeps an eye on them. It pings the\n"
        "  Docker daemon to make sure it's responsive, then lists every\n"
        "  container and reports its status. 'running' is OK; 'paused' or\n"
        "  'restarting' triggers a warning; anything else (exited, dead)\n"
        "  triggers a critical alert. Useful for catching crashed containers."
    ),
    "http": (
        "Makes an HTTP request to each URL you configure and checks whether\n"
        "  it responds within the timeout. A 2xx/3xx status code is OK; a\n"
        "  4xx/5xx, timeout, or connection refusal triggers a critical alert.\n"
        "  Use this to verify your web apps, APIs, and dashboards are up."
    ),
    "nginx": (
        "Runs three sub-checks: (1) verifies the Nginx process is running\n"
        "  (via systemctl or pgrep on the host, or container status in Docker),\n"
        "  (2) runs 'nginx -t' to validate the config has no syntax errors,\n"
        "  and (3) hits any endpoint URLs you add to confirm they're reachable."
    ),
    "certs": (
        "Connects to each domain on port 443 and checks the TLS certificate\n"
        "  expiry date. Alerts when a certificate is approaching expiry or\n"
        "  has already expired. Catches silent certbot/ACME renewal failures\n"
        "  — if your certs are renewing properly, this check never fires."
    ),
    "dns": (
        "Does a DNS lookup (getaddrinfo) for each domain you list and alerts\n"
        "  if resolution fails. Catches DNS server outages, misconfigured\n"
        "  records, or network issues that prevent name resolution."
    ),
    "ping": (
        "Sends a single ICMP ping to each host and measures round-trip time.\n"
        "  Alerts as critical if the host doesn't respond within the timeout.\n"
        "  Good for monitoring routers, gateways, NAS devices, or any host\n"
        "  where you just need to know 'is it reachable?'."
    ),
    "network": (
        "For each network interface you list, checks three things:\n"
        "  (1) link state — is the interface UP or DOWN?\n"
        "  (2) IPv4 address — does it have an IP assigned?\n"
        "  (3) TX bytes — has any traffic been transmitted?\n"
        "  Useful for VPN tunnels (tun0, wg0), bridges, or secondary NICs\n"
        "  where you need to know the link is alive and has an address."
    ),
    "home_assistant": (
        "Checks your Home Assistant instance by hitting the /api/ endpoint.\n"
        "  Optionally verifies external access (e.g. via Nabu Casa or your\n"
        "  own domain) and Google Home cloud API connectivity. If you provide\n"
        "  a long-lived access token, it can do authenticated health checks."
    ),
    "systemd": (
        "Runs 'systemctl is-active' for each unit you list. Only the 'active'\n"
        "  state is considered healthy — any other state (inactive, failed,\n"
        "  activating, deactivating, etc.) triggers an alert. Good for\n"
        "  services installed via apt/yum that aren't managed by Docker."
    ),
    "process": (
        "Uses 'pgrep -x' (or tasklist on Windows) to check if a process\n"
        "  with the exact name you specify is running. If no matching process\n"
        "  is found, it triggers a critical alert. Good for daemons that\n"
        "  don't have a systemd unit, or scripts you expect to always be up."
    ),
    "updates": (
        "Detects your system package manager (apt, dnf, or yum) and counts\n"
        "  how many updates are pending. You set thresholds — for example,\n"
        "  warn at 1+ pending update, critical at 50+. Helps you stay on\n"
        "  top of security patches without manually checking."
    ),
    "command": (
        "Runs any shell command you define and checks the exit code. Exit 0\n"
        "  means OK; non-zero means failure. You can also require a specific\n"
        "  string in the output — if it's missing, the check fails. This is\n"
        "  the escape hatch for monitoring anything labwatch doesn't have a\n"
        "  dedicated check for."
    ),
    "smart": (
        "Monitors disk health using S.M.A.R.T. data from HDDs, SSDs, and\n"
        "  NVMe drives via smartctl. On Raspberry Pi, reads SD/eMMC wear\n"
        "  levels from sysfs. Alerts on failing health, high temperatures,\n"
        "  excessive wear, or reallocated sectors."
    ),
    "system_update": (
        "Automatically runs apt-get update && apt-get upgrade (or dist-upgrade)\n"
        "  to keep your Debian/DietPi server fully patched. Optionally runs\n"
        "  autoremove to clean up unused packages and can auto-reboot when\n"
        "  a kernel update requires it."
    ),
}

# ---------------------------------------------------------------------------
# ASCII art banner
# ---------------------------------------------------------------------------

_BANNER = """\
\u2588\u2588\u2557      \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557    \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557
\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551    \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551  \u2588\u2588\u2551
\u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551 \u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551
\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551   \u2588\u2588\u2551   \u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u255a\u2588\u2588\u2588\u2554\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551   \u2588\u2588\u2551   \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u255d  \u255a\u2550\u2550\u255d\u255a\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d   \u255a\u2550\u255d    \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d
"""


def _print_banner() -> None:
    """Print a bold cyan ASCII art banner for the wizard."""
    click.secho(_BANNER, fg="cyan", bold=True)


# ---------------------------------------------------------------------------
# Module selection menu — defines all selectable modules for the checkbox
# prompt.  Each entry maps a key to its menu label, short description,
# default enabled state, wizard detail function, and the config path used
# to check current enabled state.
# ---------------------------------------------------------------------------

# Forward-declared — actual functions are defined below.  The list is
# populated after all _section_* functions exist.
MODULES: List[Dict[str, Any]] = []  # filled at module level below


def _module_selection_menu(config: dict) -> List[str]:
    """Show a questionary checkbox menu and return selected module keys.

    On re-runs, defaults reflect the currently-enabled modules.  Falls back
    to plain click prompts if questionary is unavailable (e.g. non-TTY).
    """
    try:
        import questionary
    except ImportError:
        # Fallback: ask per-module (old behavior)
        return _module_selection_fallback(config)

    choices = []
    for mod in MODULES:
        key = mod["key"]
        label = mod["label"]
        desc = mod["short_desc"]

        # Determine current enabled state from config
        if key == "autoupdate":
            is_enabled = bool(config.get("update", {}).get("compose_dirs", []))
        elif key == "system_update":
            is_enabled = config.get("update", {}).get("system", {}).get("enabled", False)
        else:
            is_enabled = config.get("checks", {}).get(key, {}).get("enabled", mod["default_enabled"])

        choices.append(questionary.Choice(
            title=f"{label} — {desc}",
            value=key,
            checked=is_enabled,
        ))

    click.echo()
    click.secho("Module selection", bold=True)
    click.secho(
        "  labwatch is made up of modules — each one monitors a different part of\n"
        "  your homelab. Pick the ones that match your setup. You can always come\n"
        "  back and change these later by running 'labwatch init' again.\n"
        "\n"
        "  Don't worry about configuration yet — just check the boxes for what you\n"
        "  want to monitor. You'll set up the details for each one in the next steps.\n"
        "\n"
        "  Use arrow keys to move, space to toggle, enter to confirm.",
        dim=True,
    )

    try:
        selected = questionary.checkbox(
            "Select which modules to enable:",
            choices=choices,
        ).ask()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(1)

    if selected is None:
        # User cancelled (Ctrl-C / Ctrl-D handled by questionary)
        raise SystemExit(1)

    return selected


def _module_selection_fallback(config: dict) -> List[str]:
    """Fallback when questionary is not available: per-module click confirms."""
    selected = []
    click.echo()
    click.secho("Module selection", bold=True)
    click.secho(
        "  labwatch is made up of modules — each one monitors a different part of\n"
        "  your homelab. Pick the ones that match your setup. You can always come\n"
        "  back and change these later by running 'labwatch init' again.\n"
        "\n"
        "  Don't worry about configuration yet — just check the boxes for what you\n"
        "  want to monitor. You'll set up the details for each one in the next steps.\n"
        "\n"
        "  (questionary not available — falling back to per-module prompts.)",
        dim=True,
    )
    for mod in MODULES:
        key = mod["key"]
        label = mod["label"]
        desc = mod["short_desc"]

        if key == "autoupdate":
            is_enabled = bool(config.get("update", {}).get("compose_dirs", []))
        elif key == "system_update":
            is_enabled = config.get("update", {}).get("system", {}).get("enabled", False)
        else:
            is_enabled = config.get("checks", {}).get(key, {}).get("enabled", mod["default_enabled"])

        state = "enabled" if is_enabled else "disabled"
        if _prompt_yn(f"  {label} ({desc}) [{state}]", default=is_enabled):
            selected.append(key)
    return selected


# Ordered list of wizard section names.
SECTION_ORDER: List[str] = [
    "hostname",
    "notifications",
    "system",
    "docker",
    "http",
    "nginx",
    "smart",
    "dns",
    "certs",
    "ping",
    "home_assistant",
    "systemd",
    "process",
    "network",
    "updates",
    "command",
    "autoupdate",
    "system_update",
    "scheduling",
]


def _print_description(check_name: str) -> None:
    """Print the description for a check section."""
    desc = CHECK_DESCRIPTIONS.get(check_name)
    if desc:
        click.secho(f"  {desc}", dim=True)


# ---------------------------------------------------------------------------
# Helper: review existing list items
# ---------------------------------------------------------------------------

def _review_existing_list(
    items: list,
    label: str,
    format_item: Callable[[Any], str],
) -> list:
    """Show existing items, ask 'Keep these?', return kept items."""
    if not items:
        return []
    click.echo(f"\n  Current {label}:")
    for i, item in enumerate(items, 1):
        click.echo(f"    {i}. {format_item(item)}")
    r = click.prompt(
        "  Enter to keep, 'n' to clear and reconfigure",
        default="", show_default=False,
    )
    if r.strip().lower() == "n":
        return []
    return list(items)


def _prompt_yn(text: str, *, default: bool) -> bool:
    """Yes/no prompt where Enter accepts the default.

    Shows '(Enter = yes, n to decline)' or '(Enter = no, y to confirm)'
    so the user always knows what pressing Enter does.
    """
    if default:
        hint = "Enter = yes, 'n' to decline"
    else:
        hint = "Enter = no, 'y' to confirm"
    r = click.prompt(f"{text}  ({hint})", default="", show_default=False)
    r = r.strip().lower()
    if not r:
        return default
    return r in ("y", "yes")


def _confirm_enable(label: str, current: bool) -> bool:
    """Prompt the user to enable/disable a module, showing current state.

    Enter = keep current state.  Type 'y' or 'n' to change.
    """
    state = "enabled" if current else "disabled"
    r = click.prompt(
        f"  {label}: {state}  (Enter to keep, y/n to change)",
        default="", show_default=False,
    )
    r = r.strip().lower()
    if not r:
        return current
    return r in ("y", "yes")


def _keep_current(label: str, summary_lines: list) -> bool:
    """Show current settings summary and ask if user wants to keep them.

    Enter = keep all.  Type 'n' to reconfigure.
    """
    click.echo(f"\n  Current {label}:")
    for line in summary_lines:
        click.echo(f"    {line}")
    r = click.prompt(
        "  Enter to keep, 'n' to change",
        default="", show_default=False,
    )
    return r.strip().lower() != "n"


# ---------------------------------------------------------------------------
# Per-section functions.  Each mutates *config* in place and reads existing
# values as defaults so that a re-run shows the previous answers.
#
# Module sections accept ``from_menu`` — when True the "Enable X?" prompt
# is skipped because the user already chose this module in the selection
# menu.  When False (the default, e.g. via --only) the prompt is shown.
# ---------------------------------------------------------------------------

def _section_hostname(config: dict) -> None:
    click.echo()
    click.secho("Hostname", bold=True)
    click.secho(
        "  Your hostname is a friendly name for this machine — like a nickname.\n"
        "  It doesn't have to match your actual computer name. It just shows up\n"
        "  in alerts and reports so you know which server is talking to you.\n"
        "  If you run labwatch on multiple machines, pick something different\n"
        "  for each one so you can tell them apart.\n"
        "\n"
        "  Examples: 'proxmox-main', 'nas', 'pi-cluster', 'media-server'",
        dim=True,
    )
    default_host = config.get("hostname") or platform.node() or "homelab"
    config["hostname"] = click.prompt("Hostname", default=default_host)


def _section_notifications(config: dict) -> None:
    click.echo()
    click.secho("Notification setup (ntfy)", bold=True)
    click.secho(
        "  Without notifications, labwatch only shows results when you manually\n"
        "  run 'labwatch check'. With notifications enabled, you get push alerts\n"
        "  straight to your phone or desktop whenever something goes wrong —\n"
        "  like a disk filling up, a container crashing, or a service going down.\n"
        "\n"
        "  ntfy (pronounced 'notify') is a free, open-source push notification\n"
        "  service. You can use the public server at ntfy.sh (no account needed)\n"
        "  or self-host your own. Install the ntfy app on your phone (Android or\n"
        "  iOS) and subscribe to your topic to start receiving alerts instantly.",
        dim=True,
    )

    existing_ntfy = config.get("notifications", {}).get("ntfy", {})
    ntfy_enabled = _confirm_enable(
        "ntfy notifications",
        existing_ntfy.get("enabled", True),
    )

    # Merge rather than replace — preserves min_severity and other keys.
    config.setdefault("notifications", {})
    config["notifications"].setdefault("ntfy", {})
    config["notifications"]["ntfy"]["enabled"] = ntfy_enabled

    if ntfy_enabled:
        existing_server = existing_ntfy.get("server", "")
        existing_topic = existing_ntfy.get("topic", "")
        if existing_server and existing_topic and _keep_current("notification settings", [
            f"server: {existing_server}",
            f"topic: {existing_topic}",
        ]):
            config["notifications"]["ntfy"]["server"] = existing_server
            config["notifications"]["ntfy"]["topic"] = existing_topic
            return

        click.secho(
            "  The server URL is where alerts are sent. Use https://ntfy.sh for\n"
            "  the free public server, or your own URL if you self-host ntfy.",
            dim=True,
        )
        config["notifications"]["ntfy"]["server"] = click.prompt(
            "ntfy server URL",
            default=existing_ntfy.get("server", "https://ntfy.sh"),
        )
        click.secho(
            "  The topic is like a channel name. Anyone who subscribes to this\n"
            "  topic will receive your alerts. Pick something unique to avoid\n"
            "  collisions on the public server (e.g. 'myname-homelab-alerts').",
            dim=True,
        )
        config["notifications"]["ntfy"]["topic"] = click.prompt(
            "ntfy topic",
            default=existing_ntfy.get("topic", "homelab_alerts"),
        )


def _section_system(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("System checks", bold=True)
    _print_description("system")

    existing = config.get("checks", {}).get("system", {})
    if from_menu:
        sys_enabled = True
    else:
        sys_enabled = _confirm_enable(
            "system checks (disk, memory, CPU)",
            existing.get("enabled", True),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("system", {})
    config["checks"]["system"]["enabled"] = sys_enabled

    if sys_enabled:
        existing_t = existing.get("thresholds", {})
        if existing_t and _keep_current("thresholds", [
            f"disk: warn {existing_t.get('disk_warning', 80)}% / crit {existing_t.get('disk_critical', 90)}%",
            f"memory: warn {existing_t.get('memory_warning', 80)}% / crit {existing_t.get('memory_critical', 90)}%",
            f"cpu: warn {existing_t.get('cpu_warning', 80)}% / crit {existing_t.get('cpu_critical', 95)}%",
        ]):
            config["checks"]["system"]["thresholds"] = dict(existing_t)
            return

        click.secho(
            "  Set thresholds for when to alert. 'Warning' sends a heads-up,\n"
            "  'critical' means something needs immediate attention.",
            dim=True,
        )
        config["checks"]["system"]["thresholds"] = {
            "disk_warning": click.prompt(
                "Disk warning threshold (%)",
                default=existing_t.get("disk_warning", 80), type=int,
            ),
            "disk_critical": click.prompt(
                "Disk critical threshold (%)",
                default=existing_t.get("disk_critical", 90), type=int,
            ),
            "memory_warning": click.prompt(
                "Memory warning threshold (%)",
                default=existing_t.get("memory_warning", 80), type=int,
            ),
            "memory_critical": click.prompt(
                "Memory critical threshold (%)",
                default=existing_t.get("memory_critical", 90), type=int,
            ),
            "cpu_warning": click.prompt(
                "CPU warning threshold (%)",
                default=existing_t.get("cpu_warning", 80), type=int,
            ),
            "cpu_critical": click.prompt(
                "CPU critical threshold (%)",
                default=existing_t.get("cpu_critical", 95), type=int,
            ),
        }


def _section_docker(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Docker checks", bold=True)
    _print_description("docker")

    existing = config.get("checks", {}).get("docker", {})

    if from_menu:
        docker_enabled = True
    else:
        containers = discover_containers()
        if containers is not None:
            click.echo(f"Found {len(containers)} Docker container(s).")
            docker_enabled = _confirm_enable(
                "Docker monitoring",
                existing.get("enabled", True),
            )
        else:
            click.echo("Docker not available on this system.")
            docker_enabled = _confirm_enable(
                "Docker monitoring (remote use)",
                existing.get("enabled", False),
            )

    config.setdefault("checks", {})

    if not docker_enabled:
        config["checks"]["docker"] = {
            "enabled": False,
            "watch_stopped": existing.get("watch_stopped", True),
            "containers": existing.get("containers", []),
        }
        return

    existing_ws = existing.get("watch_stopped", True)
    existing_containers = existing.get("containers", [])

    # Offer keep-current shortcut when settings have been configured before
    if "watch_stopped" in existing and _keep_current("Docker settings", [
        f"alert on stopped containers: {'yes' if existing_ws else 'no'}",
        f"monitoring: {', '.join(existing_containers) if existing_containers else 'all containers'}",
    ]):
        config["checks"]["docker"] = {
            "enabled": True,
            "watch_stopped": existing_ws,
            "containers": existing_containers,
        }
        return

    click.secho(
        "  Alert on stopped/exited containers? If yes, labwatch flags any\n"
        "  container that isn't 'running' as a warning or critical alert.\n"
        "  Disable if you intentionally keep some containers stopped.",
        dim=True,
    )
    watch_stopped = _prompt_yn(
        f"  Alert on stopped containers? [{'yes' if existing_ws else 'no'}]",
        default=existing_ws,
    )

    click.secho(
        "  Monitor specific containers only, or all of them?\n"
        "  Leave empty to monitor everything. Or enter container names\n"
        "  separated by commas to watch only those.",
        dim=True,
    )
    containers_str = click.prompt(
        "  Container names (comma-separated, empty = all)",
        default=", ".join(existing_containers) if existing_containers else "",
        show_default=False,
    )
    containers = [c.strip() for c in containers_str.split(",") if c.strip()] if containers_str.strip() else []

    config["checks"]["docker"] = {
        "enabled": True,
        "watch_stopped": watch_stopped,
        "containers": containers,
    }


def _section_http(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("HTTP endpoint checks", bold=True)
    _print_description("http")

    existing = config.get("checks", {}).get("http", {})
    if from_menu:
        http_enabled = True
    else:
        http_enabled = _confirm_enable(
            "HTTP endpoint checks",
            existing.get("enabled", True),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("http", {})
    config["checks"]["http"]["enabled"] = http_enabled

    existing_endpoints = existing.get("endpoints", [])

    # Review existing endpoints
    kept = _review_existing_list(
        existing_endpoints,
        "endpoints",
        lambda ep: f"{ep.get('name', '?')} ({ep.get('url', '?')})",
    )
    config["checks"]["http"]["endpoints"] = kept

    # Only suggest Docker endpoints on fresh config (no existing endpoints)
    if http_enabled and not existing_endpoints:
        containers = discover_containers()
        if containers:
            suggestions = suggest_endpoints(containers)
            if suggestions:
                click.echo("Detected services from Docker containers:")
                for i, s in enumerate(suggestions, 1):
                    click.echo(f"  {i}. {s['name']} ({s['url']})")

                if _prompt_yn("  Add these suggested endpoints?", default=True):
                    config["checks"]["http"]["endpoints"].extend(suggestions)

    if http_enabled:
        click.secho(
            "  You can add any URL you want monitored. labwatch will make an\n"
            "  HTTP request and alert if it gets no response or a 4xx/5xx error.",
            dim=True,
        )
        while _prompt_yn("  Add a custom HTTP endpoint?", default=False):
            name = click.prompt("  Endpoint name (a label for this check)")
            url = click.prompt("  URL (e.g. http://localhost:8080/health)")
            timeout = click.prompt(
                "  Timeout in seconds (how long to wait for a response)",
                default=10, type=int,
            )
            config["checks"]["http"]["endpoints"].append({
                "name": name,
                "url": url,
                "timeout": timeout,
            })


def _section_nginx(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Nginx monitoring", bold=True)
    _print_description("nginx")

    existing = config.get("checks", {}).get("nginx", {})
    if from_menu:
        nginx_enabled = True
    else:
        nginx_enabled = _confirm_enable(
            "Nginx monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("nginx", {})
    config["checks"]["nginx"]["enabled"] = nginx_enabled
    config["checks"]["nginx"].setdefault("container", existing.get("container", ""))
    config["checks"]["nginx"].setdefault("config_test", existing.get("config_test", True))

    existing_endpoints = existing.get("endpoints", [])
    kept = _review_existing_list(
        existing_endpoints,
        "endpoints",
        lambda ep: ep,
    )
    config["checks"]["nginx"]["endpoints"] = kept

    if nginx_enabled:
        existing_container = existing.get("container", "")
        existing_config_test = existing.get("config_test", True)

        # Offer keep-current shortcut when nginx has been configured before
        if "container" in existing and _keep_current("Nginx settings", [
            f"mode: {'Docker container: ' + existing_container if existing_container else 'host (systemd/direct)'}",
            f"config test (nginx -t): {'yes' if existing_config_test else 'no'}",
            f"endpoints: {len(kept)}",
        ]):
            config["checks"]["nginx"]["container"] = existing_container
            config["checks"]["nginx"]["config_test"] = existing_config_test
            return

        click.secho(
            "  If Nginx runs in Docker, enter the container name so labwatch\n"
            "  can check it via the Docker API. Leave empty if Nginx is\n"
            "  installed directly on the host (systemd/apt/yum).",
            dim=True,
        )
        container_default = existing_container or ""
        container = click.prompt(
            f"  Nginx Docker container name (empty if on host){f' [{container_default}]' if container_default else ''}",
            default=container_default, show_default=bool(container_default),
        )
        config["checks"]["nginx"]["container"] = container.strip()

        click.secho(
            "  The config test runs 'nginx -t' to check for syntax errors.\n"
            "  On the host (non-Docker) this requires root/sudo. If you don't\n"
            "  have passwordless sudo set up, disable this to avoid repeated\n"
            "  alerts. You can always run 'sudo nginx -t' manually instead.",
            dim=True,
        )
        config_test = _prompt_yn(
            f"  Enable nginx config test (nginx -t)? [{'yes' if existing_config_test else 'no'}]",
            default=existing_config_test,
        )
        config["checks"]["nginx"]["config_test"] = config_test

        click.secho(
            "  Optionally add URLs that Nginx serves. labwatch will request\n"
            "  each one and alert if it's unreachable or returns an error.",
            dim=True,
        )
        while _prompt_yn("  Add an Nginx endpoint URL to monitor?", default=False):
            url = click.prompt("    URL (e.g. https://mydomain.com)")
            config["checks"]["nginx"]["endpoints"].append(url.strip())


def _section_smart(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("S.M.A.R.T. disk health monitoring", bold=True)
    _print_description("smart")

    existing = config.get("checks", {}).get("smart", {})
    if from_menu:
        smart_enabled = True
    else:
        smart_enabled = _confirm_enable(
            "S.M.A.R.T. disk health monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("smart", {})
    config["checks"]["smart"]["enabled"] = smart_enabled
    config["checks"]["smart"].setdefault("devices", existing.get("devices", []))

    if smart_enabled:
        # Offer keep-current shortcut for thresholds
        tw = existing.get("temp_warning")
        tc = existing.get("temp_critical")
        ww = existing.get("wear_warning")
        wc = existing.get("wear_critical")
        if tw is not None and _keep_current("thresholds", [
            f"temperature: warn {tw}C / crit {tc}C",
            f"wear: warn {ww}% / crit {wc}%",
        ]):
            config["checks"]["smart"]["temp_warning"] = tw
            config["checks"]["smart"]["temp_critical"] = tc
            config["checks"]["smart"]["wear_warning"] = ww
            config["checks"]["smart"]["wear_critical"] = wc
        else:
            click.secho(
                "  Set temperature thresholds for drive alerts (in Celsius).",
                dim=True,
            )
            config["checks"]["smart"]["temp_warning"] = click.prompt(
                "  Temperature warning threshold (C)",
                default=existing.get("temp_warning", 50), type=int,
            )
            config["checks"]["smart"]["temp_critical"] = click.prompt(
                "  Temperature critical threshold (C)",
                default=existing.get("temp_critical", 60), type=int,
            )
            click.secho(
                "  Set wear thresholds for SSD/NVMe life percentage used.",
                dim=True,
            )
            config["checks"]["smart"]["wear_warning"] = click.prompt(
                "  Wear warning threshold (%)",
                default=existing.get("wear_warning", 80), type=int,
            )
            config["checks"]["smart"]["wear_critical"] = click.prompt(
                "  Wear critical threshold (%)",
                default=existing.get("wear_critical", 90), type=int,
            )

        existing_devices = existing.get("devices", [])
        kept = _review_existing_list(existing_devices, "devices", lambda d: d)
        config["checks"]["smart"]["devices"] = kept

        click.secho(
            "  Leave devices empty to auto-detect all drives. Or add specific\n"
            "  device paths (e.g. /dev/sda, /dev/nvme0).",
            dim=True,
        )
        while True:
            dev = click.prompt(
                "  Device path (empty to finish)",
                default="", show_default=False,
            )
            if not dev.strip():
                break
            config["checks"]["smart"]["devices"].append(dev.strip())


def _section_dns(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("DNS resolution monitoring", bold=True)
    _print_description("dns")

    existing = config.get("checks", {}).get("dns", {})
    if from_menu:
        dns_enabled = True
    else:
        dns_enabled = _confirm_enable(
            "DNS resolution monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("dns", {})
    config["checks"]["dns"]["enabled"] = dns_enabled

    existing_domains = existing.get("domains", [])
    kept = _review_existing_list(existing_domains, "domains", lambda d: d)
    config["checks"]["dns"]["domains"] = kept

    if dns_enabled:
        click.secho(
            "  Enter domain names to resolve. labwatch will do a DNS lookup\n"
            "  and alert if resolution fails — useful for catching DNS outages\n"
            "  or misconfigurations (e.g. google.com, mydomain.com).",
            dim=True,
        )
        while True:
            domain = click.prompt(
                "  Domain (empty to finish)",
                default="", show_default=False,
            )
            if not domain.strip():
                break
            config["checks"]["dns"]["domains"].append(domain.strip())


def _section_certs(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("TLS certificate expiry monitoring", bold=True)
    _print_description("certs")

    existing = config.get("checks", {}).get("certs", {})
    if from_menu:
        certs_enabled = True
    else:
        certs_enabled = _confirm_enable(
            "TLS certificate expiry monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("certs", {})
    config["checks"]["certs"]["enabled"] = certs_enabled

    existing_domains = existing.get("domains", [])
    kept = _review_existing_list(existing_domains, "domains", lambda d: d)
    config["checks"]["certs"]["domains"] = kept

    if certs_enabled:
        click.secho(
            "  Enter domain names whose TLS certificates you want to monitor.\n"
            "  labwatch connects on port 443 and checks the expiry date\n"
            "  (e.g. mydomain.com, nextcloud.example.org).",
            dim=True,
        )
        while True:
            domain = click.prompt(
                "  Domain (empty to finish)",
                default="", show_default=False,
            )
            if not domain.strip():
                break
            config["checks"]["certs"]["domains"].append(domain.strip())

        wd = existing.get("warn_days")
        cd = existing.get("critical_days")
        if wd is not None and _keep_current("thresholds", [
            f"warn at {wd} days / crit at {cd} days before expiry",
        ]):
            config["checks"]["certs"]["warn_days"] = wd
            config["checks"]["certs"]["critical_days"] = cd
        else:
            click.secho(
                "  Set how many days before expiry to trigger each severity level.",
                dim=True,
            )
            config["checks"]["certs"]["warn_days"] = click.prompt(
                "  Warning threshold (days before expiry)",
                default=existing.get("warn_days", 14), type=int,
            )
            config["checks"]["certs"]["critical_days"] = click.prompt(
                "  Critical threshold (days before expiry)",
                default=existing.get("critical_days", 7), type=int,
            )


def _section_ping(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Ping/connectivity monitoring", bold=True)
    _print_description("ping")

    existing = config.get("checks", {}).get("ping", {})
    if from_menu:
        ping_enabled = True
    else:
        ping_enabled = _confirm_enable(
            "ping/connectivity monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("ping", {})
    config["checks"]["ping"]["enabled"] = ping_enabled
    config["checks"]["ping"].setdefault("timeout", existing.get("timeout", 5))

    existing_hosts = existing.get("hosts", [])
    kept = _review_existing_list(existing_hosts, "hosts", lambda h: h)
    config["checks"]["ping"]["hosts"] = kept

    if ping_enabled:
        click.secho(
            "  Enter IP addresses or hostnames to ping. Good for monitoring\n"
            "  your router (192.168.1.1), a gateway, or a remote server.\n"
            "  labwatch alerts if any host stops responding.",
            dim=True,
        )
        while True:
            host = click.prompt(
                "  Host (empty to finish)",
                default="", show_default=False,
            )
            if not host.strip():
                break
            config["checks"]["ping"]["hosts"].append(host.strip())

        config["checks"]["ping"]["timeout"] = click.prompt(
            "  Ping timeout in seconds",
            default=existing.get("timeout", 5), type=int,
        )


def _section_home_assistant(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Home Assistant monitoring", bold=True)
    _print_description("home_assistant")

    existing = config.get("checks", {}).get("home_assistant", {})
    if from_menu:
        ha_enabled = True
    else:
        ha_enabled = _confirm_enable(
            "Home Assistant monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("home_assistant", {})
    config["checks"]["home_assistant"]["enabled"] = ha_enabled
    # Preserve defaults from existing config
    config["checks"]["home_assistant"].setdefault("url", existing.get("url", "http://localhost:8123"))
    config["checks"]["home_assistant"].setdefault("external_url", existing.get("external_url", ""))
    config["checks"]["home_assistant"].setdefault("token", existing.get("token", ""))
    config["checks"]["home_assistant"].setdefault("google_home", existing.get("google_home", True))

    if ha_enabled:
        existing_url = existing.get("url", "http://localhost:8123")
        existing_ext = existing.get("external_url", "")
        existing_token = existing.get("token", "")
        existing_gh = existing.get("google_home", True)

        # Offer keep-current shortcut when HA has been configured before
        if existing.get("url") and _keep_current("Home Assistant settings", [
            f"local URL: {existing_url}",
            f"external URL: {existing_ext or '(none)'}",
            f"access token: {'configured' if existing_token else '(none)'}",
            f"Google Home check: {'yes' if existing_gh else 'no'}",
        ]):
            config["checks"]["home_assistant"]["url"] = existing_url
            config["checks"]["home_assistant"]["external_url"] = existing_ext
            config["checks"]["home_assistant"]["token"] = existing_token
            config["checks"]["home_assistant"]["google_home"] = existing_gh
            return

        click.secho(
            "  The local URL is how labwatch reaches HA on your network.\n"
            "  Usually http://localhost:8123 if HA runs on this machine.",
            dim=True,
        )
        config["checks"]["home_assistant"]["url"] = click.prompt(
            "  Local HA URL",
            default=existing_url,
        )
        click.secho(
            "  If you access HA remotely (e.g. via Nabu Casa or your own\n"
            "  domain), enter that URL to also verify external access works.",
            dim=True,
        )
        ext_url = click.prompt(
            "  External HA URL (empty to skip)",
            default=existing_ext, show_default=bool(existing_ext),
        )
        config["checks"]["home_assistant"]["external_url"] = ext_url.strip()
        click.secho(
            "  A long-lived access token lets labwatch call the HA API to\n"
            "  check deeper health info. Generate one in HA under your\n"
            "  Profile -> Security -> Long-Lived Access Tokens.",
            dim=True,
        )
        if existing_token:
            click.secho("  (token is currently configured)", dim=True)
        token = click.prompt(
            "  Long-lived access token (empty to skip)",
            default=existing_token, show_default=False,
        )
        config["checks"]["home_assistant"]["token"] = token.strip()
        click.secho(
            "  If you use Google Home with HA, labwatch can verify that\n"
            "  the Google Home Cloud API endpoint is reachable.",
            dim=True,
        )
        config["checks"]["home_assistant"]["google_home"] = _prompt_yn(
            f"  Check Google Home API connectivity? [{'yes' if existing_gh else 'no'}]",
            default=existing_gh,
        )


def _section_systemd(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Systemd unit monitoring", bold=True)
    _print_description("systemd")

    existing = config.get("checks", {}).get("systemd", {})

    # Auto-detect systemd availability
    discovered = discover_systemd_units()

    if from_menu:
        systemd_enabled = True
    elif discovered is None:
        click.echo("  systemctl not available on this system.")
        systemd_enabled = _confirm_enable(
            "systemd monitoring (remote use)",
            existing.get("enabled", False),
        )
    else:
        known = [u for u in discovered if u["label"]]
        running = [u for u in discovered if u["state"] == "active"]
        click.echo(f"  Found {len(running)} running service(s)"
                    f" ({len(known)} recognized homelab service(s)).")
        systemd_enabled = _confirm_enable(
            "systemd unit monitoring",
            existing.get("enabled", bool(known)) or existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("systemd", {})
    config["checks"]["systemd"]["enabled"] = systemd_enabled

    existing_units = existing.get("units", [])
    kept = _review_existing_list(
        existing_units,
        "units",
        lambda u: u if isinstance(u, str) else f"{u.get('name', '?')} ({u.get('severity', 'critical')})",
    )
    config["checks"]["systemd"]["units"] = kept

    if not systemd_enabled:
        return

    # Build the set of already-configured unit names
    already = set()
    for u in config["checks"]["systemd"]["units"]:
        already.add(u if isinstance(u, str) else u.get("name", ""))

    # Collect all discovered unit base names for fuzzy-match later
    discovered_names: List[str] = []
    if discovered:
        discovered_names = [
            u["unit"].replace(".service", "")
            for u in discovered if u["state"] == "active"
        ]

    # --- Auto-discovered services (checkbox UI) ---
    if discovered:
        known_active = [u for u in discovered
                        if u["label"] and u["state"] == "active"
                        and u["unit"].replace(".service", "") not in already]
        other_active = [u for u in discovered
                        if u["label"] is None and u["state"] == "active"
                        and u["unit"].replace(".service", "") not in already]

        if known_active or other_active:
            _systemd_checkbox_select(
                config, already, known_active, other_active,
            )

    # --- Manual additions ---
    click.secho(
        "\n  You can also add units manually by name.\n"
        "  Use the unit name as shown by 'systemctl list-units'\n"
        "  (e.g. 'my-custom-app', 'wg-quick@wg0').",
        dim=True,
    )
    while True:
        unit = click.prompt(
            "  Unit name (empty to finish)",
            default="", show_default=False,
        )
        if not unit.strip():
            break
        name = unit.strip()

        # Validate the unit name
        _validate_systemd_unit(name, discovered_names)

        sev = click.prompt(
            f"    Severity if '{name}' is down",
            type=click.Choice(["critical", "warning"]),
            default="critical",
        )
        already.add(name)
        if sev == "critical":
            config["checks"]["systemd"]["units"].append(name)
        else:
            config["checks"]["systemd"]["units"].append({"name": name, "severity": sev})


def _systemd_checkbox_select(
    config: dict,
    already: set,
    known_active: List[Dict],
    other_active: List[Dict],
) -> None:
    """Show a questionary checkbox of discovered services.

    Known services are pre-checked; other services are unchecked.
    Falls back to per-service y/n prompts if questionary is unavailable.
    """
    try:
        import questionary
    except ImportError:
        _systemd_checkbox_fallback(config, already, known_active, other_active)
        return

    choices = []

    if known_active and other_active:
        choices.append(questionary.Separator("── Recognized homelab services ──"))

    for u in known_active:
        base = u["unit"].replace(".service", "")
        choices.append(questionary.Choice(
            title=f"{base} \u2014 {u['label']}",
            value=base,
            checked=True,
        ))

    if known_active and other_active:
        choices.append(questionary.Separator("── Other active services ──"))

    for u in other_active:
        base = u["unit"].replace(".service", "")
        choices.append(questionary.Choice(
            title=base,
            value=base,
            checked=False,
        ))

    click.echo()
    click.secho("  Select services to monitor:", bold=True)
    click.secho(
        "  Use arrow keys to move, space to toggle, enter to confirm.",
        dim=True,
    )

    try:
        selected = questionary.checkbox(
            "Services:",
            choices=choices,
        ).ask()
    except (EOFError, KeyboardInterrupt):
        return

    if selected is None:
        return

    for name in selected:
        if name not in already:
            already.add(name)
            config["checks"]["systemd"]["units"].append(name)


def _systemd_checkbox_fallback(
    config: dict,
    already: set,
    known_active: List[Dict],
    other_active: List[Dict],
) -> None:
    """Fallback when questionary is unavailable: per-service y/n prompts."""
    if known_active:
        click.echo()
        click.secho("  Detected homelab services:", bold=True)
        for i, u in enumerate(known_active, 1):
            base = u["unit"].replace(".service", "")
            click.echo(f"    {i}. {base} \u2014 {u['label']}")

        if _prompt_yn("  Add all detected services?", default=True):
            for u in known_active:
                base = u["unit"].replace(".service", "")
                already.add(base)
                config["checks"]["systemd"]["units"].append(base)
        elif _prompt_yn("  Pick individually?", default=True):
            for u in known_active:
                base = u["unit"].replace(".service", "")
                if _prompt_yn(f"    Monitor {base} ({u['label']})?", default=True):
                    already.add(base)
                    config["checks"]["systemd"]["units"].append(base)

    if other_active and _prompt_yn(
        f"\n  {len(other_active)} other running service(s) found. Browse them?",
        default=True,
    ):
        for u in other_active:
            base = u["unit"].replace(".service", "")
            if _prompt_yn(f"    Monitor {base}?", default=False):
                already.add(base)
                config["checks"]["systemd"]["units"].append(base)


def _validate_systemd_unit(name: str, discovered_names: List[str]) -> None:
    """Check if a unit exists and show suggestions on typo."""
    import subprocess as _sp

    try:
        proc = _sp.run(
            ["systemctl", "cat", name],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            return  # unit exists, nothing to warn about
    except (FileNotFoundError, _sp.TimeoutExpired):
        return  # systemctl not available — skip validation

    # Unit not found — try to suggest similar names
    suggestions = _fuzzy_match_units(name, discovered_names)
    if suggestions:
        click.secho(f"  \u26a0 Unit '{name}' not found. Did you mean one of these?", fg="yellow")
        for s in suggestions[:5]:
            click.echo(f"    - {s}")
    else:
        click.secho(f"  \u26a0 Unit '{name}' not found on this system.", fg="yellow")
    click.secho("  (Adding it anyway — you may be configuring for a remote host.)", dim=True)


def _fuzzy_match_units(name: str, candidates: List[str]) -> List[str]:
    """Return candidates that are similar to *name* (substring/prefix match)."""
    name_lower = name.lower()
    scored: List[Tuple[int, str]] = []
    for c in candidates:
        c_lower = c.lower()
        if c_lower == name_lower:
            continue
        # Exact prefix match scores highest
        if c_lower.startswith(name_lower) or name_lower.startswith(c_lower):
            scored.append((0, c))
        # Substring match
        elif name_lower in c_lower or c_lower in name_lower:
            scored.append((1, c))
        # Character-level similarity: shared chars / max length
        else:
            shared = sum(1 for ch in name_lower if ch in c_lower)
            ratio = shared / max(len(name_lower), len(c_lower))
            if ratio >= 0.6:
                scored.append((2, c))
    scored.sort()
    return [s for _, s in scored]


def _section_process(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Process monitoring", bold=True)
    _print_description("process")

    existing = config.get("checks", {}).get("process", {})
    if from_menu:
        process_enabled = True
    else:
        process_enabled = _confirm_enable(
            "process monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("process", {})
    config["checks"]["process"]["enabled"] = process_enabled

    existing_names = existing.get("names", [])
    kept = _review_existing_list(existing_names, "process names", lambda n: n)
    config["checks"]["process"]["names"] = kept

    if process_enabled:
        click.secho(
            "  Enter process names as they appear in 'ps' or 'pgrep'.\n"
            "  labwatch will alert if a process with that name isn't running\n"
            "  (e.g. 'redis-server', 'mongod', 'node').",
            dim=True,
        )
        while True:
            proc = click.prompt(
                "  Process name (empty to finish)",
                default="", show_default=False,
            )
            if not proc.strip():
                break
            config["checks"]["process"]["names"].append(proc.strip())


def _section_network(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Network interface monitoring", bold=True)
    _print_description("network")

    existing = config.get("checks", {}).get("network", {})
    if from_menu:
        network_enabled = True
    else:
        network_enabled = _confirm_enable(
            "network interface monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("network", {})
    config["checks"]["network"]["enabled"] = network_enabled

    existing_interfaces = existing.get("interfaces", [])
    kept = _review_existing_list(
        existing_interfaces,
        "interfaces",
        lambda i: f"{i.get('name', '?')} ({i.get('severity', 'critical')})",
    )
    config["checks"]["network"]["interfaces"] = kept

    if network_enabled:
        click.secho(
            "  Enter network interface names as shown by 'ip link' or 'ifconfig'.\n"
            "  Useful for VPN tunnels (tun0, wg0), bridges, or secondary NICs.\n"
            "  labwatch checks if the interface is UP and has an IP assigned.",
            dim=True,
        )
        while True:
            iface = click.prompt(
                "  Interface name (empty to finish)",
                default="", show_default=False,
            )
            if not iface.strip():
                break
            click.secho(
                f"  How severe is it if '{iface.strip()}' goes down?",
                dim=True,
            )
            sev = click.prompt(
                f"  Severity for '{iface.strip()}'",
                type=click.Choice(["critical", "warning"]),
                default="critical",
            )
            config["checks"]["network"]["interfaces"].append(
                {"name": iface.strip(), "severity": sev}
            )


def _section_updates(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Package updates monitoring", bold=True)
    _print_description("updates")

    existing = config.get("checks", {}).get("updates", {})
    if from_menu:
        updates_enabled = True
    else:
        updates_enabled = _confirm_enable(
            "package updates monitoring",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("updates", {})
    config["checks"]["updates"]["enabled"] = updates_enabled
    config["checks"]["updates"].setdefault("warning_threshold", existing.get("warning_threshold", 1))
    config["checks"]["updates"].setdefault("critical_threshold", existing.get("critical_threshold", 50))

    if updates_enabled:
        wt = existing.get("warning_threshold")
        ct = existing.get("critical_threshold")
        if wt is not None and _keep_current("thresholds", [
            f"warn at {wt}+ pending / crit at {ct}+ pending",
        ]):
            config["checks"]["updates"]["warning_threshold"] = wt
            config["checks"]["updates"]["critical_threshold"] = ct
        else:
            click.secho(
                "  Set how many pending updates trigger each severity level.\n"
                "  For example: warn at 1+ pending, critical at 50+ pending.\n"
                "  This uses your system package manager (apt, dnf, or yum).",
                dim=True,
            )
            config["checks"]["updates"]["warning_threshold"] = click.prompt(
                "  Warning threshold (number of pending updates)",
                default=existing.get("warning_threshold", 1), type=int,
            )
            config["checks"]["updates"]["critical_threshold"] = click.prompt(
                "  Critical threshold (number of pending updates)",
                default=existing.get("critical_threshold", 50), type=int,
            )


def _section_command(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Custom command checks", bold=True)
    _print_description("command")

    existing = config.get("checks", {}).get("command", {})
    if from_menu:
        command_enabled = True
    else:
        command_enabled = _confirm_enable(
            "custom command checks",
            existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("command", {})
    config["checks"]["command"]["enabled"] = command_enabled

    existing_commands = existing.get("commands", [])
    kept = _review_existing_list(
        existing_commands,
        "commands",
        lambda c: f"{c.get('name', '?')}: {c.get('command', '?')}",
    )
    config["checks"]["command"]["commands"] = kept

    if command_enabled:
        click.secho(
            "  Define shell commands that labwatch runs on each check cycle.\n"
            "  A non-zero exit code means failure. You can also require a\n"
            "  specific string in the output to consider the check passing.",
            dim=True,
        )
        while _prompt_yn("  Add a command check?", default=not bool(kept)):
            cmd_name = click.prompt("    Check name (a label for this check)")
            cmd_command = click.prompt("    Shell command to run (e.g. 'curl -sf http://...')")
            cmd_expect = click.prompt(
                "    Expected output substring (alert if missing, empty to skip)",
                default="", show_default=False,
            )
            cmd_severity = click.prompt(
                "    Failure severity",
                type=click.Choice(["critical", "warning"]),
                default="critical",
            )
            entry: Dict[str, Any] = {"name": cmd_name, "command": cmd_command, "severity": cmd_severity}
            if cmd_expect.strip():
                entry["expect_output"] = cmd_expect.strip()
            config["checks"]["command"]["commands"].append(entry)


def _section_autoupdate(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Docker auto-updates", bold=True)
    click.secho(
        "  labwatch can automatically pull the latest Docker images and\n"
        "  restart your Compose services. It runs 'docker compose pull'\n"
        "  followed by 'docker compose up -d' in each configured directory.",
        dim=True,
    )

    existing_dirs = config.get("update", {}).get("compose_dirs", [])

    # Review existing dirs
    kept = _review_existing_list(existing_dirs, "compose directories", lambda d: d)
    config.setdefault("update", {})
    config["update"]["compose_dirs"] = kept

    if from_menu:
        update_enabled = True
    else:
        update_enabled = _confirm_enable("Docker Compose auto-updates", bool(kept))

    if update_enabled:
        _configure_auto_updates(config)
    elif not from_menu:
        # Not selected and not from menu — clear dirs
        pass


def _section_system_update(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("System updates (apt-get)", bold=True)
    _print_description("system_update")

    existing = config.get("update", {}).get("system", {})

    if from_menu:
        su_enabled = True
    else:
        su_enabled = _confirm_enable(
            "automated system updates",
            existing.get("enabled", False),
        )

    config.setdefault("update", {})
    config["update"].setdefault("system", {})
    config["update"]["system"]["enabled"] = su_enabled

    if not su_enabled:
        return

    existing_mode = existing.get("mode", "safe")
    existing_autoremove = existing.get("autoremove", True)
    existing_auto_reboot = existing.get("auto_reboot", False)

    if "mode" in existing and _keep_current("system update settings", [
        f"mode: {existing_mode} ({'apt-get upgrade' if existing_mode == 'safe' else 'apt-get dist-upgrade'})",
        f"autoremove: {'yes' if existing_autoremove else 'no'}",
        f"auto-reboot: {'yes' if existing_auto_reboot else 'no'}",
    ]):
        config["update"]["system"]["mode"] = existing_mode
        config["update"]["system"]["autoremove"] = existing_autoremove
        config["update"]["system"]["auto_reboot"] = existing_auto_reboot
        return

    click.secho(
        "  'safe' runs apt-get upgrade (never removes packages or installs\n"
        "  new ones). 'full' runs apt-get dist-upgrade (may remove/install\n"
        "  packages as needed for major upgrades).",
        dim=True,
    )
    mode = click.prompt(
        "  Update mode",
        type=click.Choice(["safe", "full"]),
        default=existing_mode,
    )
    config["update"]["system"]["mode"] = mode

    config["update"]["system"]["autoremove"] = _prompt_yn(
        f"  Run autoremove after upgrade? [{'yes' if existing_autoremove else 'no'}]",
        default=existing_autoremove,
    )

    click.secho(
        "  Auto-reboot will schedule 'shutdown -r +1' if a kernel update\n"
        "  requires a reboot. The 1-minute delay lets notifications send first.",
        dim=True,
    )
    config["update"]["system"]["auto_reboot"] = _prompt_yn(
        f"  Auto-reboot when required? [{'yes' if existing_auto_reboot else 'no'}]",
        default=existing_auto_reboot,
    )


def _section_scheduling(config: dict) -> None:
    _offer_scheduling(config)


# Map section names to their functions.
SECTION_FUNCTIONS: Dict[str, Callable] = {
    "hostname": _section_hostname,
    "notifications": _section_notifications,
    "system": _section_system,
    "docker": _section_docker,
    "http": _section_http,
    "nginx": _section_nginx,
    "smart": _section_smart,
    "dns": _section_dns,
    "certs": _section_certs,
    "ping": _section_ping,
    "home_assistant": _section_home_assistant,
    "systemd": _section_systemd,
    "process": _section_process,
    "network": _section_network,
    "updates": _section_updates,
    "command": _section_command,
    "autoupdate": _section_autoupdate,
    "system_update": _section_system_update,
    "scheduling": _section_scheduling,
}

# ---------------------------------------------------------------------------
# Populate MODULES list — used by the module selection menu.
# Order here determines the order in the checkbox list.
# ---------------------------------------------------------------------------

MODULES.extend([
    {
        "key": "system",
        "label": "System checks",
        "short_desc": "disk space, memory, CPU load",
        "default_enabled": True,
        "wizard_fn": _section_system,
        "config_path": "checks.system",
    },
    {
        "key": "docker",
        "label": "Docker",
        "short_desc": "container status monitoring",
        "default_enabled": True,
        "wizard_fn": _section_docker,
        "config_path": "checks.docker",
    },
    {
        "key": "http",
        "label": "HTTP endpoints",
        "short_desc": "URL availability checks",
        "default_enabled": True,
        "wizard_fn": _section_http,
        "config_path": "checks.http",
    },
    {
        "key": "nginx",
        "label": "Nginx",
        "short_desc": "process, config test, endpoints",
        "default_enabled": False,
        "wizard_fn": _section_nginx,
        "config_path": "checks.nginx",
    },
    {
        "key": "smart",
        "label": "S.M.A.R.T.",
        "short_desc": "disk health monitoring (SSD, HDD, SD cards)",
        "default_enabled": False,
        "wizard_fn": _section_smart,
        "config_path": "checks.smart",
    },
    {
        "key": "dns",
        "label": "DNS resolution",
        "short_desc": "domain lookup checks",
        "default_enabled": False,
        "wizard_fn": _section_dns,
        "config_path": "checks.dns",
    },
    {
        "key": "certs",
        "label": "TLS certificates",
        "short_desc": "certificate expiry monitoring",
        "default_enabled": False,
        "wizard_fn": _section_certs,
        "config_path": "checks.certs",
    },
    {
        "key": "ping",
        "label": "Ping",
        "short_desc": "host reachability checks",
        "default_enabled": False,
        "wizard_fn": _section_ping,
        "config_path": "checks.ping",
    },
    {
        "key": "home_assistant",
        "label": "Home Assistant",
        "short_desc": "HA instance health monitoring",
        "default_enabled": False,
        "wizard_fn": _section_home_assistant,
        "config_path": "checks.home_assistant",
    },
    {
        "key": "systemd",
        "label": "Systemd units",
        "short_desc": "service status monitoring",
        "default_enabled": False,
        "wizard_fn": _section_systemd,
        "config_path": "checks.systemd",
    },
    {
        "key": "process",
        "label": "Process",
        "short_desc": "running process checks",
        "default_enabled": False,
        "wizard_fn": _section_process,
        "config_path": "checks.process",
    },
    {
        "key": "network",
        "label": "Network interfaces",
        "short_desc": "link state, IP, traffic checks",
        "default_enabled": False,
        "wizard_fn": _section_network,
        "config_path": "checks.network",
    },
    {
        "key": "updates",
        "label": "Package updates",
        "short_desc": "pending system updates count",
        "default_enabled": False,
        "wizard_fn": _section_updates,
        "config_path": "checks.updates",
    },
    {
        "key": "command",
        "label": "Custom commands",
        "short_desc": "arbitrary shell command checks",
        "default_enabled": False,
        "wizard_fn": _section_command,
        "config_path": "checks.command",
    },
    {
        "key": "autoupdate",
        "label": "Docker auto-updates",
        "short_desc": "pull & restart Compose services",
        "default_enabled": False,
        "wizard_fn": _section_autoupdate,
        "config_path": "update.compose_dirs",
    },
    {
        "key": "system_update",
        "label": "System updates",
        "short_desc": "automated apt-get upgrade (Debian/DietPi)",
        "default_enabled": False,
        "wizard_fn": _section_system_update,
        "config_path": "update.system",
    },
])


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_wizard(config_path: Optional[Path] = None, only: Optional[str] = None) -> None:
    """Walk the user through initial configuration."""
    path = config_path or default_config_path()
    is_rerun = path.exists()

    # Validate --only
    if only is not None:
        requested = [s.strip() for s in only.split(",") if s.strip()]
        invalid = [s for s in requested if s not in SECTION_FUNCTIONS]
        if invalid:
            valid_list = ", ".join(SECTION_ORDER)
            click.secho(
                f"Unknown section(s): {', '.join(invalid)}\n"
                f"Valid sections: {valid_list}",
                fg="red",
            )
            raise SystemExit(1)
        if not is_rerun:
            click.secho(
                "No existing config found. Run labwatch init first (without --only).",
                fg="red",
            )
            raise SystemExit(1)

    click.echo()
    click.secho("labwatch setup wizard", bold=True)
    click.secho("=" * 40)
    click.echo()
    click.echo(f"  Config file: {path}")

    if is_rerun:
        config = load_config(path)
        click.secho(
            "  Existing config loaded — press Enter at any prompt to keep\n"
            "  the current value. Only type if you want to change something.",
            dim=True,
        )
    else:
        config = deep_merge(DEFAULT_CONFIG, {})
        click.secho(
            "  This wizard will create a YAML config file at the path above.\n"
            "  You can edit it later with any text editor, or re-run this wizard.",
            dim=True,
        )

    click.echo()

    if only is not None:
        # --only mode: run only the named sections (old behavior)
        sections_to_run = [s.strip() for s in only.split(",") if s.strip()]
        for section_name in SECTION_ORDER:
            if section_name not in sections_to_run:
                continue
            SECTION_FUNCTIONS[section_name](config)

        # Save
        if "scheduling" not in sections_to_run:
            click.echo()
            saved_path = save_config(config, path)
            click.secho(f"Config saved to {saved_path}", fg="green", bold=True)
            _print_summary(config, saved_path)
        return

    # --- Full wizard flow with module selection menu ---

    # 1. ASCII art banner
    _print_banner()

    # 2. Module selection menu (the exciting part — pick what to monitor first)
    selected_modules = _module_selection_menu(config)

    # 3. Hostname
    _section_hostname(config)

    # 4. Notifications
    _section_notifications(config)

    # All module keys for reference
    all_module_keys = [mod["key"] for mod in MODULES]

    # 5. Detail configuration for each selected module (in menu order)
    for mod in MODULES:
        key = mod["key"]
        if key in selected_modules:
            mod["wizard_fn"](config, from_menu=True)

    # 6. Disable unselected modules
    for key in all_module_keys:
        if key not in selected_modules:
            if key == "autoupdate":
                config.setdefault("update", {})
                config["update"]["compose_dirs"] = []
            elif key == "system_update":
                config.setdefault("update", {}).setdefault("system", {})
                config["update"]["system"]["enabled"] = False
            else:
                config.setdefault("checks", {}).setdefault(key, {})
                config["checks"][key]["enabled"] = False

    # 7. Scheduling
    _section_scheduling(config)


def _configure_auto_updates(config: dict) -> None:
    """Handle the Docker Compose auto-update configuration flow."""
    compose_projects = discover_compose_dirs()

    if compose_projects:
        click.echo(f"\nFound {len(compose_projects)} Docker Compose project(s):")
        for i, (project, working_dir) in enumerate(compose_projects, 1):
            click.echo(f"  {i}. {project} ({working_dir})")

        if _prompt_yn("\n  Include all for auto-updates?", default=True):
            config["update"]["compose_dirs"] = [d for _, d in compose_projects]
        else:
            for project, working_dir in compose_projects:
                if _prompt_yn(f"  Include {project} ({working_dir})?", default=False):
                    config["update"]["compose_dirs"].append(working_dir)
    else:
        if compose_projects is None:
            click.echo("Docker not available — skipping auto-detection.")
        else:
            click.echo("No Docker Compose projects detected from running containers.")

        base_dir = click.prompt(
            "Base directory to scan for compose files (empty to skip)",
            default="", show_default=False,
        )
        if base_dir.strip():
            _scan_base_dir(config, base_dir.strip())

    # Always offer manual additions
    while _prompt_yn("  Add additional directories manually?", default=False):
        dir_path = click.prompt("  Compose directory")
        if dir_path.strip():
            config["update"]["compose_dirs"].append(dir_path.strip())

    if not config["update"]["compose_dirs"]:
        click.echo("  No directories added — skipping auto-updates.")


def _scan_base_dir(config: dict, base_dir: str) -> None:
    """Scan a base directory for subdirectories containing compose files."""
    base = Path(base_dir)
    if not base.is_dir():
        click.echo(f"  '{base_dir}' is not a directory — skipping.")
        return

    compose_names = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
    found = []
    for child in sorted(base.iterdir()):
        if child.is_dir():
            for name in compose_names:
                if (child / name).exists():
                    found.append(str(child))
                    break

    if not found:
        click.echo(f"  No compose files found under {base_dir}.")
        return

    click.echo(f"  Found {len(found)} compose directory(ies):")
    for d in found:
        click.echo(f"    {d}")

    if _prompt_yn("  Include all?", default=True):
        config["update"]["compose_dirs"].extend(found)
    else:
        for d in found:
            if _prompt_yn(f"  Include {d}?", default=False):
                config["update"]["compose_dirs"].append(d)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section_break() -> None:
    """Print a consistent visual separator between wizard stages."""
    click.echo()
    click.secho("=" * 40)
    click.echo()


# ---------------------------------------------------------------------------
# Post-config summary
# ---------------------------------------------------------------------------

def _print_summary(config: dict, config_path: Path) -> None:
    """Print a recap of what was configured."""
    _section_break()
    click.secho("What you set up", bold=True)
    click.secho("-" * 40)
    click.echo(f"  Config file: {config_path}")
    click.secho(
        "  ^ Edit this file to change settings without re-running the wizard.",
        dim=True,
    )

    # Notifications
    ntfy = config.get("notifications", {}).get("ntfy", {})
    if ntfy.get("enabled"):
        server = ntfy.get("server", "https://ntfy.sh")
        topic = ntfy.get("topic", "homelab_alerts")
        click.echo(f"  Notifications: ntfy -> {server}/{topic}")
    else:
        click.echo("  Notifications: disabled")

    # Enabled/disabled checks
    checks = config.get("checks", {})
    all_check_names = [
        "system", "docker", "http", "nginx", "smart", "dns", "certs", "ping",
        "home_assistant", "systemd", "process", "network", "updates", "command",
    ]
    enabled = [n for n in all_check_names if checks.get(n, {}).get("enabled")]
    disabled = [n for n in all_check_names if not checks.get(n, {}).get("enabled")]

    if enabled:
        click.echo(f"  Enabled checks:  {', '.join(enabled)}")
    if disabled:
        click.secho(f"  Disabled checks: {', '.join(disabled)}", dim=True)

    # Auto-updates
    compose_dirs = config.get("update", {}).get("compose_dirs", [])
    if compose_dirs:
        click.echo(f"  Auto-update dirs: {len(compose_dirs)} compose project(s)")
    else:
        click.secho("  Auto-updates: not configured", dim=True)


# ---------------------------------------------------------------------------
# Notification test
# ---------------------------------------------------------------------------

def _offer_notification_test(config: dict) -> None:
    """Offer to send a test notification so the user knows it works."""
    ntfy = config.get("notifications", {}).get("ntfy", {})
    if not ntfy.get("enabled"):
        return

    _section_break()
    click.secho("Test notifications", bold=True)
    click.secho(
        "  Send a test alert to verify your ntfy setup is working.",
        dim=True,
    )
    if not _prompt_yn("  Send a test notification now?", default=True):
        click.echo("  Skipped. You can test later with: labwatch notify 'Test' 'Hello from labwatch'")
        return

    try:
        from labwatch.notifications import get_notifiers

        notifiers = get_notifiers(config)
        if not notifiers:
            click.secho("  No notifiers configured.", fg="yellow")
            return

        for notifier in notifiers:
            notifier.send(
                "labwatch test",
                f"Setup complete on {config.get('hostname', 'unknown')}. Notifications are working!",
            )
            click.secho(f"  Sent via {notifier.name}", fg="green")
    except Exception as e:
        click.secho(f"  Failed to send: {e}", fg="red")
        click.echo("  Check your ntfy config. You can retry with: labwatch notify 'Test' 'Hello'")


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

# Checks grouped by recommended frequency.  Only tiers with at least one
# enabled check are shown to the user.
#
# Each tuple: (default_interval, human_label, check_names, frequency_choices)
#
# Rationale:
#   fast  (1m)  - link-state changes are time-sensitive
#   med   (5m)  - service reachability; you want to know quickly
#   slow  (30m) - resource usage / daemon state / disk health; less volatile
#   daily (1d)  - package updates; no rush
SCHEDULE_TIERS: List[Tuple[str, str, List[str], List[Tuple[str, str]]]] = [
    ("1m", "every minute", ["network"], [
        ("1m", "Every minute (recommended)"),
        ("5m", "Every 5 minutes"),
        ("15m", "Every 15 minutes"),
        ("30m", "Every 30 minutes"),
    ]),
    ("5m", "every 5 min", ["http", "dns", "certs", "ping", "nginx"], [
        ("5m", "Every 5 minutes (recommended)"),
        ("15m", "Every 15 minutes"),
        ("30m", "Every 30 minutes"),
        ("1h", "Hourly"),
    ]),
    ("30m", "every 30 min", ["system", "docker", "home_assistant", "systemd", "process", "command", "smart"], [
        ("30m", "Every 30 minutes (recommended)"),
        ("1h", "Hourly"),
        ("4h", "Every 4 hours"),
        ("1d", "Daily"),
    ]),
    ("1d", "daily", ["updates"], [
        ("1d", "Daily (recommended)"),
        ("1w", "Weekly"),
    ]),
]

# Frequency choices for auto-updates
_UPDATE_CHOICES: List[Tuple[str, str]] = [
    ("1d", "Daily (recommended)"),
    ("1w", "Weekly"),
]

_SYSTEM_UPDATE_CHOICES: List[Tuple[str, str]] = [
    ("1w", "Weekly (recommended)"),
    ("1d", "Daily"),
]


def _offer_scheduling(config: dict) -> None:
    """Explain the execution model and offer to install cron entries."""
    # Save config before scheduling (so cron jobs use up-to-date config)
    path = default_config_path()
    saved_path = save_config(config, path)
    click.echo()
    click.secho(f"Config saved to {saved_path}", fg="green", bold=True)

    _print_summary(config, saved_path)

    _section_break()
    click.secho("Scheduling", bold=True)
    click.echo(
        "  labwatch is not a daemon — it runs once and exits.\n"
        "  To monitor continuously, you need a cron job (or Task Scheduler\n"
        "  on Windows) that calls 'labwatch check' on an interval.\n"
        "\n"
        "  Cron is a built-in Linux tool that runs commands automatically on\n"
        "  a schedule — like a task scheduler. This lets labwatch check your\n"
        "  server every few minutes without you having to remember."
    )

    # Offer notification test first — good to know it works before scheduling
    _offer_notification_test(config)

    # Build the recommended schedule from enabled checks
    checks = config.get("checks", {})
    compose_dirs = config.get("update", {}).get("compose_dirs", [])
    system_update_enabled = config.get("update", {}).get("system", {}).get("enabled", False)

    # (interval, label, modules, choices) — only tiers with enabled checks
    active_tiers: List[Tuple[str, str, List[str], List[Tuple[str, str]]]] = []
    for default_interval, label, tier_checks, choices in SCHEDULE_TIERS:
        enabled_in_tier = [c for c in tier_checks if checks.get(c, {}).get("enabled")]
        if enabled_in_tier:
            active_tiers.append((default_interval, label, enabled_in_tier, choices))

    if not active_tiers and not compose_dirs and not system_update_enabled:
        click.echo()
        click.echo("  No checks enabled — nothing to schedule.")
        _print_done()
        return

    # Show recommended schedule
    click.echo()
    click.secho("  Recommended schedule:", bold=True)
    for interval, label, modules, _choices in active_tiers:
        click.echo(f"    {label:14s}  labwatch check --only {','.join(modules)}")
    if compose_dirs:
        click.echo(f"    {'daily':14s}  labwatch docker-update")
    if system_update_enabled:
        click.echo(f"    {'weekly':14s}  labwatch system-update")

    # On Windows, we can't install cron — just print the commands
    if sys.platform == "win32":
        click.echo()
        click.echo("  Windows detected — cron is not available.")
        click.echo("  Use Task Scheduler to run these commands on an interval.")
        _print_done()
        return

    # Three-way choice: accept / customize / none
    click.echo()
    click.echo("  [A] Accept recommended schedule  (Enter = A)")
    click.echo("  [C] Customize intervals")
    click.echo("  [N] Skip — set up later")
    choice = click.prompt(
        "  Choice",
        type=click.Choice(["A", "C", "N"], case_sensitive=False),
        default="A",
        show_choices=False,
        prompt_suffix=" (Enter = Accept): ",
    ).upper()

    if choice == "N":
        click.echo()
        click.echo("  Skipped. You can set it up later with:")
        for interval, _label, modules, _choices in active_tiers:
            click.echo(f"    labwatch schedule check --every {interval} --only {','.join(modules)}")
        if compose_dirs:
            click.echo(f"    labwatch schedule docker-update --every 1d")
        if system_update_enabled:
            click.echo(f"    labwatch schedule system-update --every 1w")
        click.echo(f"    labwatch schedule list    # see what's installed")
        _print_done()
        return

    # Build final schedule — either recommended defaults or customized
    # schedule_plan: list of (interval, modules_list)
    schedule_plan: List[Tuple[str, List[str]]] = []
    update_interval = "1d"
    system_update_interval = "1w"

    if choice == "C":
        click.echo()
        for default_interval, _label, modules, choices in active_tiers:
            modules_str = ", ".join(modules)
            click.echo(f"  {modules_str}:")
            for i, (intv, desc) in enumerate(choices, 1):
                click.echo(f"    [{i}] {desc}")
            idx = click.prompt(
                "    Choice",
                type=click.IntRange(1, len(choices)),
                default=1,
            )
            selected_interval = choices[idx - 1][0]
            schedule_plan.append((selected_interval, modules))

        if compose_dirs:
            click.echo(f"  Docker auto-updates:")
            for i, (intv, desc) in enumerate(_UPDATE_CHOICES, 1):
                click.echo(f"    [{i}] {desc}")
            idx = click.prompt(
                "    Choice",
                type=click.IntRange(1, len(_UPDATE_CHOICES)),
                default=1,
            )
            update_interval = _UPDATE_CHOICES[idx - 1][0]

        if system_update_enabled:
            click.echo(f"  System updates:")
            for i, (intv, desc) in enumerate(_SYSTEM_UPDATE_CHOICES, 1):
                click.echo(f"    [{i}] {desc}")
            idx = click.prompt(
                "    Choice",
                type=click.IntRange(1, len(_SYSTEM_UPDATE_CHOICES)),
                default=1,
            )
            system_update_interval = _SYSTEM_UPDATE_CHOICES[idx - 1][0]
    else:
        # Accept recommended
        for default_interval, _label, modules, _choices in active_tiers:
            schedule_plan.append((default_interval, modules))

    # Install cron entries
    click.echo()
    try:
        from labwatch import scheduler

        for interval, modules in schedule_plan:
            line = scheduler.add_entry("check", interval, modules=modules)
            click.secho(f"  Installed: {line}", fg="green")

        if compose_dirs:
            line = scheduler.add_entry("docker-update", update_interval)
            click.secho(f"  Installed: {line}", fg="green")

        if system_update_enabled:
            line = scheduler.add_entry("system-update", system_update_interval)
            click.secho(f"  Installed: {line}", fg="green")

        click.echo()
        click.secho("Cron schedule installed.", fg="green", bold=True)
        click.echo("  labwatch schedule list     # view installed entries")
        click.echo("  labwatch schedule remove   # uninstall everything")
    except Exception as e:
        click.secho(f"  Failed to install cron entries: {e}", fg="red")
        click.echo("  You can install them manually:")
        for interval, modules in schedule_plan:
            click.echo(f"    labwatch schedule check --every {interval} --only {','.join(modules)}")
        if compose_dirs:
            click.echo(f"    labwatch schedule docker-update --every {update_interval}")
        if system_update_enabled:
            click.echo(f"    labwatch schedule system-update --every {system_update_interval}")

    _print_done()


def _print_done() -> None:
    """Print the final completion block."""
    _section_break()
    click.secho("Setup complete!", fg="green", bold=True)
    click.echo()
    click.secho("Useful commands", bold=True)
    click.echo("  labwatch check               # run all checks once")
    click.echo("  labwatch check --only system  # run one check module")
    click.echo("  labwatch summarize            # see what's being monitored")
    click.echo("  labwatch validate             # verify your config")
    click.echo("  labwatch edit                 # open config in your editor")
    click.echo("  labwatch schedule list        # view cron schedule")
    click.echo("  labwatch init                 # re-run this wizard")
