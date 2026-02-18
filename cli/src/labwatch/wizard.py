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
}

# ---------------------------------------------------------------------------
# ASCII art banner
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    """Print a bold cyan ASCII art banner for the wizard."""
    banner = (
        "  _       _                _       _\n"
        " | | __ _| |____      __  | |_ ___| |__\n"
        " | |/ _` | '_ \\ \\ /\\ / / / _` / __| '_ \\\n"
        " | | (_| | |_) \\ V  V / | (_| \\__ \\ | | |\n"
        " |_|\\__,_|_.__/ \\_/\\_/   \\__,_|___/_| |_|\n"
    )
    click.secho(banner, fg="cyan", bold=True)


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
        else:
            is_enabled = config.get("checks", {}).get(key, {}).get("enabled", mod["default_enabled"])

        if click.confirm(f"  Enable {label} ({desc})?", default=is_enabled):
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
    "ping",
    "home_assistant",
    "systemd",
    "process",
    "network",
    "updates",
    "command",
    "autoupdate",
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
    if click.confirm(f"  Keep these {label}?", default=True):
        return list(items)
    return []


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
    ntfy_enabled = click.confirm(
        "Enable ntfy notifications?",
        default=existing_ntfy.get("enabled", True),
    )

    # Merge rather than replace — preserves min_severity and other keys.
    config.setdefault("notifications", {})
    config["notifications"].setdefault("ntfy", {})
    config["notifications"]["ntfy"]["enabled"] = ntfy_enabled

    if ntfy_enabled:
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
        sys_enabled = click.confirm(
            "Enable system checks (disk, memory, CPU)?",
            default=existing.get("enabled", True),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("system", {})
    config["checks"]["system"]["enabled"] = sys_enabled

    if sys_enabled:
        click.secho(
            "  Set thresholds for when to alert. 'Warning' sends a heads-up,\n"
            "  'critical' means something needs immediate attention.",
            dim=True,
        )
        existing_t = existing.get("thresholds", {})
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
            docker_enabled = click.confirm(
                "Enable Docker monitoring?",
                default=existing.get("enabled", True),
            )
        else:
            click.echo("Docker not available on this system.")
            docker_enabled = click.confirm(
                "Enable Docker monitoring anyway (for remote use)?",
                default=existing.get("enabled", False),
            )

    config.setdefault("checks", {})
    config["checks"]["docker"] = {
        "enabled": docker_enabled,
        "watch_stopped": existing.get("watch_stopped", True),
        "containers": existing.get("containers", []),
    }


def _section_http(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("HTTP endpoint checks", bold=True)
    _print_description("http")

    existing = config.get("checks", {}).get("http", {})
    if from_menu:
        http_enabled = True
    else:
        http_enabled = click.confirm(
            "Enable HTTP endpoint checks?",
            default=existing.get("enabled", True),
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

                if click.confirm("Add these suggested endpoints?", default=True):
                    config["checks"]["http"]["endpoints"].extend(suggestions)

    if http_enabled:
        click.secho(
            "  You can add any URL you want monitored. labwatch will make an\n"
            "  HTTP request and alert if it gets no response or a 4xx/5xx error.",
            dim=True,
        )
        while click.confirm("Add a custom HTTP endpoint?", default=False):
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
        nginx_enabled = click.confirm(
            "Enable Nginx monitoring?",
            default=existing.get("enabled", False),
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
        click.secho(
            "  If Nginx runs in Docker, enter the container name so labwatch\n"
            "  can check it via the Docker API. Leave empty if Nginx is\n"
            "  installed directly on the host (systemd/apt/yum).",
            dim=True,
        )
        container = click.prompt(
            "  Nginx Docker container name (empty if installed on host)",
            default=existing.get("container", ""), show_default=False,
        )
        config["checks"]["nginx"]["container"] = container.strip()

        click.secho(
            "  The config test runs 'nginx -t' to check for syntax errors.\n"
            "  On the host (non-Docker) this requires root/sudo. If you don't\n"
            "  have passwordless sudo set up, disable this to avoid repeated\n"
            "  alerts. You can always run 'sudo nginx -t' manually instead.",
            dim=True,
        )
        config_test = click.confirm(
            "  Enable nginx config test (nginx -t)?",
            default=existing.get("config_test", bool(container)),
        )
        config["checks"]["nginx"]["config_test"] = config_test

        click.secho(
            "  Optionally add URLs that Nginx serves. labwatch will request\n"
            "  each one and alert if it's unreachable or returns an error.",
            dim=True,
        )
        while click.confirm("  Add an Nginx endpoint URL to monitor?", default=False):
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
        smart_enabled = click.confirm(
            "Enable S.M.A.R.T. disk health monitoring?",
            default=existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("smart", {})
    config["checks"]["smart"]["enabled"] = smart_enabled
    config["checks"]["smart"].setdefault("devices", existing.get("devices", []))

    if smart_enabled:
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
        dns_enabled = click.confirm(
            "Enable DNS resolution monitoring?",
            default=existing.get("enabled", False),
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


def _section_ping(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Ping/connectivity monitoring", bold=True)
    _print_description("ping")

    existing = config.get("checks", {}).get("ping", {})
    if from_menu:
        ping_enabled = True
    else:
        ping_enabled = click.confirm(
            "Enable ping/connectivity monitoring?",
            default=existing.get("enabled", False),
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


def _section_home_assistant(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Home Assistant monitoring", bold=True)
    _print_description("home_assistant")

    existing = config.get("checks", {}).get("home_assistant", {})
    if from_menu:
        ha_enabled = True
    else:
        ha_enabled = click.confirm(
            "Enable Home Assistant monitoring?",
            default=existing.get("enabled", False),
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
        click.secho(
            "  The local URL is how labwatch reaches HA on your network.\n"
            "  Usually http://localhost:8123 if HA runs on this machine.",
            dim=True,
        )
        config["checks"]["home_assistant"]["url"] = click.prompt(
            "  Local HA URL",
            default=existing.get("url", "http://localhost:8123"),
        )
        click.secho(
            "  If you access HA remotely (e.g. via Nabu Casa or your own\n"
            "  domain), enter that URL to also verify external access works.",
            dim=True,
        )
        ext_url = click.prompt(
            "  External HA URL (empty to skip)",
            default=existing.get("external_url", ""), show_default=False,
        )
        config["checks"]["home_assistant"]["external_url"] = ext_url.strip()
        click.secho(
            "  A long-lived access token lets labwatch call the HA API to\n"
            "  check deeper health info. Generate one in HA under your\n"
            "  Profile -> Security -> Long-Lived Access Tokens.",
            dim=True,
        )
        token = click.prompt(
            "  Long-lived access token (empty to skip deep checks)",
            default=existing.get("token", ""), show_default=False,
        )
        config["checks"]["home_assistant"]["token"] = token.strip()
        click.secho(
            "  If you use Google Home with HA, labwatch can verify that\n"
            "  the Google Home Cloud API endpoint is reachable.",
            dim=True,
        )
        config["checks"]["home_assistant"]["google_home"] = click.confirm(
            "  Check Google Home API connectivity?",
            default=existing.get("google_home", True),
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
        systemd_enabled = click.confirm(
            "Enable systemd monitoring anyway (for remote use)?",
            default=existing.get("enabled", False),
        )
    else:
        known = [u for u in discovered if u["label"]]
        running = [u for u in discovered if u["state"] == "active"]
        click.echo(f"  Found {len(running)} running service(s)"
                    f" ({len(known)} recognized homelab service(s)).")
        systemd_enabled = click.confirm(
            "Enable systemd unit monitoring?",
            default=existing.get("enabled", bool(known)) or existing.get("enabled", False),
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

    # --- Auto-discovered services ---
    if discovered:
        # Show recognized homelab services first (these are the ones users
        # most likely want), then other active services.
        known_active = [u for u in discovered
                        if u["label"] and u["state"] == "active"
                        and u["unit"].replace(".service", "") not in already]
        if known_active:
            click.echo()
            click.secho("  Detected homelab services:", bold=True)
            for i, u in enumerate(known_active, 1):
                base = u["unit"].replace(".service", "")
                click.echo(f"    {i}. {base} — {u['label']}")

            if click.confirm("  Add all detected services?", default=True):
                for u in known_active:
                    base = u["unit"].replace(".service", "")
                    already.add(base)
                    config["checks"]["systemd"]["units"].append(base)
            elif click.confirm("  Pick individually?", default=True):
                for u in known_active:
                    base = u["unit"].replace(".service", "")
                    if click.confirm(f"    Monitor {base} ({u['label']})?", default=True):
                        already.add(base)
                        config["checks"]["systemd"]["units"].append(base)

        # Offer other running (non-known) services
        other_active = [u for u in discovered
                        if u["label"] is None and u["state"] == "active"
                        and u["unit"].replace(".service", "") not in already]
        if other_active and click.confirm(
            f"\n  {len(other_active)} other running service(s) found. Browse them?",
            default=False,
        ):
            for u in other_active:
                base = u["unit"].replace(".service", "")
                if click.confirm(f"    Monitor {base}?", default=False):
                    already.add(base)
                    config["checks"]["systemd"]["units"].append(base)

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


def _section_process(config: dict, *, from_menu: bool = False) -> None:
    click.echo()
    click.secho("Process monitoring", bold=True)
    _print_description("process")

    existing = config.get("checks", {}).get("process", {})
    if from_menu:
        process_enabled = True
    else:
        process_enabled = click.confirm(
            "Enable process monitoring?",
            default=existing.get("enabled", False),
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
        network_enabled = click.confirm(
            "Enable network interface monitoring?",
            default=existing.get("enabled", False),
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
        updates_enabled = click.confirm(
            "Enable package updates monitoring?",
            default=existing.get("enabled", False),
        )

    config.setdefault("checks", {})
    config["checks"].setdefault("updates", {})
    config["checks"]["updates"]["enabled"] = updates_enabled
    config["checks"]["updates"].setdefault("warning_threshold", existing.get("warning_threshold", 1))
    config["checks"]["updates"].setdefault("critical_threshold", existing.get("critical_threshold", 50))

    if updates_enabled:
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
        command_enabled = click.confirm(
            "Enable custom command checks?",
            default=existing.get("enabled", False),
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
        while click.confirm("  Add a command check?", default=True):
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
        update_enabled = click.confirm("Configure Docker Compose auto-updates?", default=bool(kept))

    if update_enabled:
        _configure_auto_updates(config)
    elif not from_menu:
        # Not selected and not from menu — clear dirs
        pass


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
    "ping": _section_ping,
    "home_assistant": _section_home_assistant,
    "systemd": _section_systemd,
    "process": _section_process,
    "network": _section_network,
    "updates": _section_updates,
    "command": _section_command,
    "autoupdate": _section_autoupdate,
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
            "  Existing config loaded. Current values shown as defaults\n"
            "  in [brackets] — press Enter to keep them.",
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

        if click.confirm("\nInclude all for auto-updates?", default=True):
            config["update"]["compose_dirs"] = [d for _, d in compose_projects]
        else:
            for project, working_dir in compose_projects:
                if click.confirm(f"  Include {project} ({working_dir})?", default=False):
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
    while click.confirm("Add additional directories manually?", default=False):
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

    if click.confirm("  Include all?", default=True):
        config["update"]["compose_dirs"].extend(found)
    else:
        for d in found:
            if click.confirm(f"  Include {d}?", default=False):
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
        "system", "docker", "http", "nginx", "smart", "dns", "ping",
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
    if not click.confirm("Send a test notification now?", default=True):
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
    ("5m", "every 5 min", ["http", "dns", "ping", "nginx"], [
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

    # (interval, label, modules, choices) — only tiers with enabled checks
    active_tiers: List[Tuple[str, str, List[str], List[Tuple[str, str]]]] = []
    for default_interval, label, tier_checks, choices in SCHEDULE_TIERS:
        enabled_in_tier = [c for c in tier_checks if checks.get(c, {}).get("enabled")]
        if enabled_in_tier:
            active_tiers.append((default_interval, label, enabled_in_tier, choices))

    if not active_tiers and not compose_dirs:
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
        click.echo(f"    {'daily':14s}  labwatch update")

    # On Windows, we can't install cron — just print the commands
    if sys.platform == "win32":
        click.echo()
        click.echo("  Windows detected — cron is not available.")
        click.echo("  Use Task Scheduler to run these commands on an interval.")
        _print_done()
        return

    # Three-way choice: accept / customize / none
    click.echo()
    choice = click.prompt(
        "  Schedule checks",
        type=click.Choice(["A", "C", "N"], case_sensitive=False),
        default="A",
        show_choices=False,
        prompt_suffix="? [A]ccept recommended / [C]ustomize / [N]one: ",
    ).upper()

    if choice == "N":
        click.echo()
        click.echo("  Skipped. You can set it up later with:")
        for interval, _label, modules, _choices in active_tiers:
            click.echo(f"    labwatch schedule check --every {interval} --only {','.join(modules)}")
        if compose_dirs:
            click.echo(f"    labwatch schedule update --every 1d")
        click.echo(f"    labwatch schedule list    # see what's installed")
        _print_done()
        return

    # Build final schedule — either recommended defaults or customized
    # schedule_plan: list of (interval, modules_list)
    schedule_plan: List[Tuple[str, List[str]]] = []
    update_interval = "1d"

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
            click.echo(f"  Auto-updates:")
            for i, (intv, desc) in enumerate(_UPDATE_CHOICES, 1):
                click.echo(f"    [{i}] {desc}")
            idx = click.prompt(
                "    Choice",
                type=click.IntRange(1, len(_UPDATE_CHOICES)),
                default=1,
            )
            update_interval = _UPDATE_CHOICES[idx - 1][0]
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

    _print_done()


def _print_done() -> None:
    """Print the final completion block."""
    _section_break()
    click.secho("Setup complete!", fg="green", bold=True)
    click.echo()
    click.secho("Useful commands", bold=True)
    click.echo("  labwatch check               # run all checks once")
    click.echo("  labwatch check --only system  # run one check module")
    click.echo("  labwatch config               # show config path and summary")
    click.echo("  labwatch config --validate    # verify your config")
    click.echo("  labwatch summarize            # see what's being monitored")
    click.echo("  labwatch schedule list        # view cron schedule")
    click.echo("  labwatch init                 # re-run this wizard")
