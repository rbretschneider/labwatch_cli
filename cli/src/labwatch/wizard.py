"""Interactive setup wizard for labwatch."""

import platform
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click

from labwatch.config import DEFAULT_CONFIG, default_config_path, save_config, deep_merge
from labwatch.discovery import discover_compose_dirs, discover_containers, suggest_endpoints

# Short descriptions shown before each check's enable prompt.
CHECK_DESCRIPTIONS = {
    "system": (
        "Monitors disk usage, memory, and CPU. Alerts when resources hit"
        " warning/critical thresholds."
    ),
    "docker": (
        "Checks that the Docker daemon is healthy and monitors container"
        " status. Can alert on stopped or unhealthy containers."
    ),
    "http": (
        "Pings your services over HTTP and alerts if they don't respond or"
        " return unexpected status codes."
    ),
    "nginx": (
        "Verifies Nginx is running, validates config (nginx -t), and checks"
        " that endpoints are reachable."
    ),
    "dns": (
        "Resolves domain names and alerts if DNS lookups start failing."
    ),
    "ping": (
        "Sends ICMP pings to hosts and alerts if they stop responding. Good"
        " for routers, gateways, remote servers."
    ),
    "network": (
        "Monitors network interfaces (VPN tunnels, WireGuard, etc.) for link"
        " state, IP assignment, and activity."
    ),
    "home_assistant": (
        "Checks HA API health, external URL access, and Google Home"
        " integration if configured."
    ),
    "systemd": (
        "Monitors systemd units and alerts if they stop running. Good for"
        " services not managed by Docker."
    ),
    "process": (
        "Checks that specific processes are running by name."
    ),
    "updates": (
        "Checks for pending system package updates (apt/dnf/yum) and reports"
        " how many are waiting."
    ),
    "command": (
        "Runs arbitrary shell commands and checks exit codes or output."
        " Escape hatch for anything else."
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

    if path.exists():
        if not click.confirm(f"Config already exists at {path}. Overwrite?", default=False):
            click.echo("Aborted.")
            return

    config = dict(DEFAULT_CONFIG)

    # Hostname
    default_host = platform.node() or "homelab"
    config["hostname"] = click.prompt("Hostname", default=default_host)

    # ntfy configuration
    click.echo()
    click.secho("Notification setup (ntfy)", bold=True)
    ntfy_enabled = click.confirm("Enable ntfy notifications?", default=True)
    config["notifications"] = {"ntfy": {"enabled": ntfy_enabled}}

    if ntfy_enabled:
        config["notifications"]["ntfy"]["server"] = click.prompt(
            "ntfy server URL", default="https://ntfy.sh"
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
        config["checks"]["system"]["thresholds"] = {
            "disk_warning": click.prompt("Disk warning threshold (%)", default=80, type=int),
            "disk_critical": click.prompt("Disk critical threshold (%)", default=90, type=int),
            "memory_warning": click.prompt("Memory warning threshold (%)", default=80, type=int),
            "memory_critical": click.prompt("Memory critical threshold (%)", default=90, type=int),
            "cpu_load_multiplier": click.prompt("CPU load multiplier", default=2, type=int),
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
        while click.confirm("Add a custom HTTP endpoint?", default=False):
            name = click.prompt("  Endpoint name")
            url = click.prompt("  URL")
            timeout = click.prompt("  Timeout (seconds)", default=10, type=int)
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
    config["checks"]["nginx"] = {"enabled": nginx_enabled, "container": "", "endpoints": []}

    if nginx_enabled:
        container = click.prompt(
            "  Nginx Docker container name (empty for systemd/process mode)",
            default="", show_default=False,
        )
        config["checks"]["nginx"]["container"] = container.strip()

        while click.confirm("  Add an Nginx endpoint URL to monitor?", default=False):
            url = click.prompt("    URL")
            config["checks"]["nginx"]["endpoints"].append(url.strip())

    # DNS checks
    click.echo()
    click.secho("DNS resolution monitoring", bold=True)
    _print_description("dns")
    dns_enabled = click.confirm("Enable DNS resolution monitoring?", default=False)
    config["checks"]["dns"] = {"enabled": dns_enabled, "domains": []}

    if dns_enabled:
        click.echo("  Enter domains to monitor (one per prompt).")
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
        click.echo("  Enter hosts to ping (one per prompt, e.g. 8.8.8.8).")
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
        config["checks"]["home_assistant"]["url"] = click.prompt(
            "  Local HA URL", default="http://localhost:8123"
        )
        ext_url = click.prompt(
            "  External HA URL (empty to skip)",
            default="", show_default=False,
        )
        config["checks"]["home_assistant"]["external_url"] = ext_url.strip()
        token = click.prompt(
            "  Long-lived access token (empty to skip deep checks)",
            default="", show_default=False,
        )
        config["checks"]["home_assistant"]["token"] = token.strip()
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
        click.echo("  Enter systemd unit names to monitor (one per prompt).")
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
        click.echo("  Enter process names to monitor (one per prompt).")
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
        click.echo("  Enter interface names to monitor (one per prompt, e.g. tun0, wg0).")
        while True:
            iface = click.prompt(
                "  Interface name (empty to finish)",
                default="", show_default=False,
            )
            if not iface.strip():
                break
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
        while click.confirm("  Add a command check?", default=True):
            cmd_name = click.prompt("    Check name")
            cmd_command = click.prompt("    Command to run")
            cmd_expect = click.prompt(
                "    Expected output substring (empty to skip)",
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
    update_enabled = click.confirm("Configure Docker Compose auto-updates?", default=False)
    config["update"] = {"compose_dirs": []}

    if update_enabled:
        _configure_auto_updates(config)

    # Save
    click.echo()
    saved_path = save_config(config, path)
    click.secho(f"Config saved to {saved_path}", fg="green", bold=True)

    # Show what was configured
    _print_summary(config)

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
# Post-config summary
# ---------------------------------------------------------------------------

def _print_summary(config: dict) -> None:
    """Print a recap of what was configured."""
    click.echo()
    click.secho("What you set up", bold=True)
    click.secho("-" * 40)

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

    click.echo()
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

# Checks grouped by recommended frequency. Each check belongs to exactly one
# tier.  When building the schedule, only tiers with at least one enabled
# check are shown to the user.
#
# Rationale:
#   fast  (1m)  - link-state changes are time-sensitive
#   med   (5m)  - service reachability; you want to know quickly
#   slow  (30m) - resource usage / daemon state; less volatile
#   daily (1d)  - package updates; no rush
SCHEDULE_TIERS: List[Tuple[str, str, List[str]]] = [
    ("1m",  "every minute",  ["network"]),
    ("5m",  "every 5 min",   ["http", "dns", "ping", "nginx"]),
    ("30m", "every 30 min",  ["system", "docker", "home_assistant", "systemd", "process", "command"]),
    ("1d",  "daily",         ["updates"]),
]


def _offer_scheduling(config: dict) -> None:
    """Explain the execution model and offer to install cron entries."""
    click.echo()
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

    schedule: List[Tuple[str, str, List[str]]] = []  # (interval, label, modules)
    for interval, label, tier_checks in SCHEDULE_TIERS:
        enabled_in_tier = [c for c in tier_checks if checks.get(c, {}).get("enabled")]
        if enabled_in_tier:
            schedule.append((interval, label, enabled_in_tier))

    if not schedule and not compose_dirs:
        click.echo()
        click.echo("  No checks enabled — nothing to schedule.")
        _print_manual_next_steps()
        return

    # Show recommended schedule
    click.echo()
    click.secho("  Recommended schedule:", bold=True)
    for interval, label, modules in schedule:
        click.echo(f"    {label:14s}  labwatch check --only {','.join(modules)}")
    if compose_dirs:
        click.echo(f"    {'daily':14s}  labwatch update")

    # On Windows, we can't install cron — just print the commands
    if sys.platform == "win32":
        click.echo()
        click.echo("  Windows detected — cron is not available.")
        click.echo("  Use Task Scheduler to run these commands on an interval.")
        _print_manual_next_steps()
        return

    click.echo()
    if not click.confirm("Install this cron schedule now?", default=True):
        click.echo()
        click.echo("  You can set it up later with:")
        for interval, _label, modules in schedule:
            click.echo(f"    labwatch schedule check --every {interval} --only {','.join(modules)}")
        if compose_dirs:
            click.echo(f"    labwatch schedule update --every 1d")
        click.echo(f"    labwatch schedule list    # see what's installed")
        _print_manual_next_steps()
        return

    # Install cron entries
    try:
        from labwatch import scheduler

        for interval, _label, modules in schedule:
            line = scheduler.add_entry("check", interval, modules=modules)
            click.secho(f"  Installed: {line}", fg="green")

        if compose_dirs:
            line = scheduler.add_entry("update", "1d")
            click.secho(f"  Installed: {line}", fg="green")

        click.echo()
        click.secho("Scheduling complete.", fg="green", bold=True)
        click.echo("  labwatch schedule list     # view installed entries")
        click.echo("  labwatch schedule remove   # uninstall everything")
    except Exception as e:
        click.secho(f"  Failed to install cron entries: {e}", fg="red")
        click.echo("  You can install them manually:")
        for interval, _label, modules in schedule:
            click.echo(f"    labwatch schedule check --every {interval} --only {','.join(modules)}")
        if compose_dirs:
            click.echo(f"    labwatch schedule update --every 1d")

    _print_manual_next_steps()


def _print_manual_next_steps() -> None:
    """Print final guidance."""
    click.echo()
    click.secho("Useful commands", bold=True)
    click.echo("  labwatch check               # run all checks once")
    click.echo("  labwatch check --only system  # run one check module")
    click.echo("  labwatch config --validate    # verify your config")
    click.echo("  labwatch summarize            # see what's being monitored")
    click.echo("  labwatch schedule list        # view cron schedule")
