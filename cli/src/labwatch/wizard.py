"""Interactive setup wizard for labwatch."""

import platform
from pathlib import Path
from typing import Optional

import click

from labwatch.config import DEFAULT_CONFIG, default_config_path, save_config, deep_merge
from labwatch.discovery import discover_containers, suggest_endpoints


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

    # Custom command checks
    click.echo()
    click.secho("Custom command checks", bold=True)
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
        click.echo("Enter paths to Docker Compose directories (one per prompt).")
        while True:
            dir_path = click.prompt(
                "  Compose directory (empty to finish)",
                default="", show_default=False,
            )
            if not dir_path.strip():
                break
            config["update"]["compose_dirs"].append(dir_path.strip())

        if not config["update"]["compose_dirs"]:
            click.echo("  No directories added — skipping auto-updates.")

    # Save
    click.echo()
    saved_path = save_config(config, path)
    click.secho(f"Config saved to {saved_path}", fg="green", bold=True)
    click.echo()
    click.echo("Next steps:")
    click.echo(f"  labwatch config --validate   # verify config")
    click.echo(f"  labwatch check --only system  # test system checks")
    click.echo(f"  labwatch check               # run all checks")
