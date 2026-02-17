"""Interactive setup wizard for labwatch."""

import platform
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click

from labwatch.config import DEFAULT_CONFIG, default_config_path, save_config, deep_merge
from labwatch.discovery import discover_compose_dirs, discover_containers, suggest_endpoints

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
        "Pings the Docker daemon to make sure it's responsive, then lists\n"
        "  every container and reports its status. 'running' is OK; 'paused'\n"
        "  or 'restarting' triggers a warning; anything else (exited, dead)\n"
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
}


def _print_description(check_name: str) -> None:
    """Print the description for a check section."""
    desc = CHECK_DESCRIPTIONS.get(check_name)
    if desc:
        click.secho(f"  {desc}", dim=True)


def run_wizard(config_path: Optional[Path] = None) -> None:
    """Walk the user through initial configuration."""
    path = config_path or default_config_path()

    click.echo()
    click.secho("labwatch setup wizard", bold=True)
    click.secho("=" * 40)
    click.echo()
    click.echo(f"  Config file: {path}")
    click.secho(
        "  This wizard will create a YAML config file at the path above.\n"
        "  You can edit it later with any text editor, or re-run this wizard.",
        dim=True,
    )
    click.echo()

    if path.exists():
        if not click.confirm(f"Config already exists at {path}. Overwrite?", default=False):
            click.echo("Aborted.")
            return

    config = dict(DEFAULT_CONFIG)

    # Hostname
    click.secho("Hostname", bold=True)
    click.secho(
        "  This name identifies your server in alerts and reports.\n"
        "  Use something recognizable — e.g. 'proxmox', 'nas', 'pi-cluster'.",
        dim=True,
    )
    default_host = platform.node() or "homelab"
    config["hostname"] = click.prompt("Hostname", default=default_host)

    # ntfy configuration
    click.echo()
    click.secho("Notification setup (ntfy)", bold=True)
    click.secho(
        "  ntfy (pronounced 'notify') is a simple push notification service.\n"
        "  When a check fails, labwatch sends an alert to your phone/desktop\n"
        "  via ntfy. You can self-host ntfy or use the free public server at\n"
        "  ntfy.sh. Install the ntfy app on your phone to receive alerts.",
        dim=True,
    )
    ntfy_enabled = click.confirm("Enable ntfy notifications?", default=True)
    config["notifications"] = {"ntfy": {"enabled": ntfy_enabled}}

    if ntfy_enabled:
        click.secho(
            "  The server URL is where alerts are sent. Use https://ntfy.sh for\n"
            "  the free public server, or your own URL if you self-host ntfy.",
            dim=True,
        )
        config["notifications"]["ntfy"]["server"] = click.prompt(
            "ntfy server URL", default="https://ntfy.sh"
        )
        click.secho(
            "  The topic is like a channel name. Anyone who subscribes to this\n"
            "  topic will receive your alerts. Pick something unique to avoid\n"
            "  collisions on the public server (e.g. 'myname-homelab-alerts').",
            dim=True,
        )
        config["notifications"]["ntfy"]["topic"] = click.prompt(
            "ntfy topic", default="homelab_alerts"
        )

    # System checks
    click.echo()
    click.secho("System checks", bold=True)
    _print_description("system")
    sys_enabled = click.confirm("Enable system checks (disk, memory, CPU)?", default=True)
    config["checks"] = {"system": {"enabled": sys_enabled}}

    if sys_enabled:
        click.secho(
            "  Set thresholds for when to alert. 'Warning' sends a heads-up,\n"
            "  'critical' means something needs immediate attention.",
            dim=True,
        )
        config["checks"]["system"]["thresholds"] = {
            "disk_warning": click.prompt("Disk warning threshold (%)", default=80, type=int),
            "disk_critical": click.prompt("Disk critical threshold (%)", default=90, type=int),
            "memory_warning": click.prompt("Memory warning threshold (%)", default=80, type=int),
            "memory_critical": click.prompt("Memory critical threshold (%)", default=90, type=int),
            "cpu_load_multiplier": click.prompt(
                "CPU load multiplier (alert when load exceeds CPU count * this value)",
                default=2, type=int,
            ),
        }

    # Docker checks
    click.echo()
    click.secho("Docker checks", bold=True)
    _print_description("docker")

    containers = discover_containers()
    if containers is not None:
        click.echo(f"Found {len(containers)} Docker container(s).")
        docker_enabled = click.confirm("Enable Docker monitoring?", default=True)
    else:
        click.echo("Docker not available on this system.")
        docker_enabled = click.confirm("Enable Docker monitoring anyway (for remote use)?", default=False)

    config["checks"]["docker"] = {
        "enabled": docker_enabled,
        "watch_stopped": True,
        "containers": [],
    }

    # HTTP checks
    click.echo()
    click.secho("HTTP endpoint checks", bold=True)
    _print_description("http")
    http_enabled = click.confirm("Enable HTTP endpoint checks?", default=True)
    config["checks"]["http"] = {"enabled": http_enabled, "endpoints": []}

    if http_enabled and containers:
        suggestions = suggest_endpoints(containers)
        if suggestions:
            click.echo("Detected services from Docker containers:")
            for i, s in enumerate(suggestions, 1):
                click.echo(f"  {i}. {s['name']} ({s['url']})")

            if click.confirm("Add these suggested endpoints?", default=True):
                config["checks"]["http"]["endpoints"] = suggestions

    if http_enabled:
        click.secho(
            "  You can add any URL you want monitored. labwatch will make an\n"
            "  HTTP request and alert if it gets no response or a 4xx/5xx error.",
            dim=True,
        )
        while click.confirm("Add a custom HTTP endpoint?", default=False):
            name = click.prompt("  Endpoint name (a label for this check)")
            url = click.prompt("  URL (e.g. http://localhost:8080/health)")
            timeout = click.prompt("  Timeout in seconds (how long to wait for a response)", default=10, type=int)
            config["checks"]["http"]["endpoints"].append({
                "name": name,
                "url": url,
                "timeout": timeout,
            })

    # Nginx checks
    click.echo()
    click.secho("Nginx monitoring", bold=True)
    _print_description("nginx")
    nginx_enabled = click.confirm("Enable Nginx monitoring?", default=False)
    config["checks"]["nginx"] = {
        "enabled": nginx_enabled,
        "container": "",
        "config_test": True,
        "endpoints": [],
    }

    if nginx_enabled:
        click.secho(
            "  If Nginx runs in Docker, enter the container name so labwatch\n"
            "  can check it via the Docker API. Leave empty if Nginx is\n"
            "  installed directly on the host (systemd/apt/yum).",
            dim=True,
        )
        container = click.prompt(
            "  Nginx Docker container name (empty if installed on host)",
            default="", show_default=False,
        )
        config["checks"]["nginx"]["container"] = container.strip()

        click.secho(
            "  The config test runs 'nginx -t' to check for syntax errors.\n"
            "  On the host (non-Docker) this requires root/sudo. If you don't\n"
            "  have passwordless sudo set up, disable this to avoid repeated\n"
            "  alerts. You can always run 'sudo nginx -t' manually instead.",
            dim=True,
        )
        config_test = click.confirm("  Enable nginx config test (nginx -t)?", default=bool(container))
        config["checks"]["nginx"]["config_test"] = config_test

        click.secho(
            "  Optionally add URLs that Nginx serves. labwatch will request\n"
            "  each one and alert if it's unreachable or returns an error.",
            dim=True,
        )
        while click.confirm("  Add an Nginx endpoint URL to monitor?", default=False):
            url = click.prompt("    URL (e.g. https://mydomain.com)")
            config["checks"]["nginx"]["endpoints"].append(url.strip())

    # DNS checks
    click.echo()
    click.secho("DNS resolution monitoring", bold=True)
    _print_description("dns")
    dns_enabled = click.confirm("Enable DNS resolution monitoring?", default=False)
    config["checks"]["dns"] = {"enabled": dns_enabled, "domains": []}

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

    # Ping checks
    click.echo()
    click.secho("Ping/connectivity monitoring", bold=True)
    _print_description("ping")
    ping_enabled = click.confirm("Enable ping/connectivity monitoring?", default=False)
    config["checks"]["ping"] = {"enabled": ping_enabled, "hosts": [], "timeout": 5}

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

    # Home Assistant checks
    click.echo()
    click.secho("Home Assistant monitoring", bold=True)
    _print_description("home_assistant")
    ha_enabled = click.confirm("Enable Home Assistant monitoring?", default=False)
    config["checks"]["home_assistant"] = {
        "enabled": ha_enabled,
        "url": "http://localhost:8123",
        "external_url": "",
        "token": "",
        "google_home": True,
    }

    if ha_enabled:
        click.secho(
            "  The local URL is how labwatch reaches HA on your network.\n"
            "  Usually http://localhost:8123 if HA runs on this machine.",
            dim=True,
        )
        config["checks"]["home_assistant"]["url"] = click.prompt(
            "  Local HA URL", default="http://localhost:8123"
        )
        click.secho(
            "  If you access HA remotely (e.g. via Nabu Casa or your own\n"
            "  domain), enter that URL to also verify external access works.",
            dim=True,
        )
        ext_url = click.prompt(
            "  External HA URL (empty to skip)",
            default="", show_default=False,
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
            default="", show_default=False,
        )
        config["checks"]["home_assistant"]["token"] = token.strip()
        click.secho(
            "  If you use Google Home with HA, labwatch can verify that\n"
            "  the Google Home Cloud API endpoint is reachable.",
            dim=True,
        )
        config["checks"]["home_assistant"]["google_home"] = click.confirm(
            "  Check Google Home API connectivity?", default=True,
        )

    # Systemd unit monitoring
    click.echo()
    click.secho("Systemd unit monitoring", bold=True)
    _print_description("systemd")
    systemd_enabled = click.confirm("Enable systemd unit monitoring?", default=False)
    config["checks"]["systemd"] = {"enabled": systemd_enabled, "units": []}

    if systemd_enabled:
        click.secho(
            "  Enter the names of systemd services you want monitored.\n"
            "  Use the unit name as shown by 'systemctl list-units'\n"
            "  (e.g. 'nginx', 'sshd', 'tailscaled').",
            dim=True,
        )
        while True:
            unit = click.prompt(
                "  Unit name (empty to finish)",
                default="", show_default=False,
            )
            if not unit.strip():
                break
            config["checks"]["systemd"]["units"].append(unit.strip())

    # Process monitoring
    click.echo()
    click.secho("Process monitoring", bold=True)
    _print_description("process")
    process_enabled = click.confirm("Enable process monitoring?", default=False)
    config["checks"]["process"] = {"enabled": process_enabled, "names": []}

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

    # Network interface monitoring
    click.echo()
    click.secho("Network interface monitoring", bold=True)
    _print_description("network")
    network_enabled = click.confirm("Enable network interface monitoring?", default=False)
    config["checks"]["network"] = {"enabled": network_enabled, "interfaces": []}

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

    # Updates check
    click.echo()
    click.secho("Package updates monitoring", bold=True)
    _print_description("updates")
    updates_enabled = click.confirm("Enable package updates monitoring?", default=False)
    config["checks"]["updates"] = {
        "enabled": updates_enabled,
        "warning_threshold": 1,
        "critical_threshold": 50,
    }

    if updates_enabled:
        click.secho(
            "  Set how many pending updates trigger each severity level.\n"
            "  For example: warn at 1+ pending, critical at 50+ pending.\n"
            "  This uses your system package manager (apt, dnf, or yum).",
            dim=True,
        )
        config["checks"]["updates"]["warning_threshold"] = click.prompt(
            "  Warning threshold (number of pending updates)", default=1, type=int,
        )
        config["checks"]["updates"]["critical_threshold"] = click.prompt(
            "  Critical threshold (number of pending updates)", default=50, type=int,
        )

    # Custom command checks
    click.echo()
    click.secho("Custom command checks", bold=True)
    _print_description("command")
    command_enabled = click.confirm("Enable custom command checks?", default=False)
    config["checks"]["command"] = {"enabled": command_enabled, "commands": []}

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
            entry = {"name": cmd_name, "command": cmd_command, "severity": cmd_severity}
            if cmd_expect.strip():
                entry["expect_output"] = cmd_expect.strip()
            config["checks"]["command"]["commands"].append(entry)

    # Docker auto-updates
    click.echo()
    click.secho("Docker auto-updates", bold=True)
    click.secho(
        "  labwatch can automatically pull the latest Docker images and\n"
        "  restart your Compose services. It runs 'docker compose pull'\n"
        "  followed by 'docker compose up -d' in each configured directory.",
        dim=True,
    )
    update_enabled = click.confirm("Configure Docker Compose auto-updates?", default=False)
    config["update"] = {"compose_dirs": []}

    if update_enabled:
        _configure_auto_updates(config)

    # Save
    click.echo()
    saved_path = save_config(config, path)
    click.secho(f"Config saved to {saved_path}", fg="green", bold=True)

    # Show what was configured
    _print_summary(config, saved_path)

    # Scheduling
    _offer_scheduling(config)


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
        "system", "docker", "http", "nginx", "dns", "ping",
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
#   slow  (30m) - resource usage / daemon state; less volatile
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
    ("30m", "every 30 min", ["system", "docker", "home_assistant", "systemd", "process", "command"], [
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
    _section_break()
    click.secho("Scheduling", bold=True)
    click.echo(
        "  labwatch is not a daemon — it runs once and exits.\n"
        "  To monitor continuously, you need a cron job (or Task Scheduler\n"
        "  on Windows) that calls 'labwatch check' on an interval."
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
            line = scheduler.add_entry("update", update_interval)
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
            click.echo(f"    labwatch schedule update --every {update_interval}")

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
