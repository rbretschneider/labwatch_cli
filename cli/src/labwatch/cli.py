"""CLI entry point for labwatch."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from labwatch import __version__
from labwatch.checks import get_check_classes
from labwatch.config import load_config, validate_config, default_config_path
from labwatch.models import Severity


def _validate_modules(modules, ctx):
    """Validate --only module names against the check registry. Exits on error."""
    if not modules:
        return
    valid = set(get_check_classes().keys())
    bad = [m for m in modules if m not in valid]
    if bad:
        console = _get_console(ctx)
        console.print(f"[red]Unknown check module(s): {', '.join(bad)}[/red]")
        console.print(f"Valid modules: {', '.join(sorted(valid))}")
        raise SystemExit(1)


def _get_config(ctx) -> dict:
    """Load config using the path from context (or default)."""
    path = ctx.obj.get("config_path")
    if path:
        path = Path(path)
    return load_config(path)


def _get_console(ctx) -> Console:
    """Create a Rich console respecting --no-color, with UTF-8 forced on Windows."""
    no_color = ctx.obj.get("no_color", False)
    # Force UTF-8 output to avoid Windows cp1252 encoding errors with Rich
    if sys.platform == "win32":
        out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        return Console(file=out, no_color=no_color, force_terminal=True)
    return Console(no_color=no_color)


@click.group()
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Path to config file.")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress output on success (for cron).")
@click.pass_context
def cli(ctx, config_path, no_color, verbose, quiet):
    """labwatch - Homelab monitoring CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["no_color"] = no_color
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


@cli.command()
def version():
    """Show labwatch version."""
    click.echo(f"labwatch {__version__}")


@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion_cmd(shell):
    """Print shell completion script.

    \b
    Usage:
      labwatch completion bash >> ~/.bashrc
      labwatch completion zsh  >> ~/.zshrc
      labwatch completion fish > ~/.config/fish/completions/labwatch.fish
    """
    env_var = "_LABWATCH_COMPLETE"
    source_map = {"bash": "bash_source", "zsh": "zsh_source", "fish": "fish_source"}
    env = {**os.environ, env_var: source_map[shell]}
    result = subprocess.run(
        ["labwatch"], env=env, capture_output=True, text=True,
    )
    if result.stdout:
        click.echo(result.stdout)
    else:
        # Fallback: print the eval-based snippet
        snippets = {
            "bash": f'eval "$({env_var}={source_map[shell]} labwatch)"',
            "zsh": f'eval "$({env_var}={source_map[shell]} labwatch)"',
            "fish": f'set -x {env_var} {source_map[shell]}; labwatch | source',
        }
        click.echo(snippets[shell])


@cli.command("config")
@click.option("--validate", "do_validate", is_flag=True,
              help="Validate the config file.")
@click.option("--edit", "do_edit", is_flag=True,
              help="Open the config file in your default editor.")
@click.pass_context
def config_cmd(ctx, do_validate, do_edit):
    """Show or validate the current configuration."""
    console = _get_console(ctx)
    config_path = ctx.obj.get("config_path")
    resolved_path = Path(config_path) if config_path else default_config_path()

    if do_edit:
        if not resolved_path.exists():
            console.print(f"[red]Config file does not exist:[/red] {resolved_path}")
            console.print("Run [bold]labwatch init[/bold] to create it.")
            raise SystemExit(1)
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if not editor:
            if sys.platform == "win32":
                editor = "notepad"
            else:
                editor = "nano"
        click.edit(filename=str(resolved_path), editor=editor)
        return

    cfg = _get_config(ctx)

    if do_validate:
        errors = validate_config(cfg)
        if errors:
            console.print("[red]Config validation failed:[/red]")
            for err in errors:
                console.print(f"  [red]\u2718[/red] {err}")
            raise SystemExit(1)
        else:
            console.print(f"[green]\u2714[/green] Config is valid: {resolved_path}")
            return

    console.print(f"[bold]Config file:[/bold] {resolved_path}")
    console.print(f"[bold]Exists:[/bold] {resolved_path.exists()}")
    console.print()

    table = Table(title="Configuration Summary")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("hostname", cfg.get("hostname", ""))

    ntfy = cfg.get("notifications", {}).get("ntfy", {})
    table.add_row("ntfy.enabled", str(ntfy.get("enabled", False)))
    table.add_row("ntfy.server", ntfy.get("server", ""))
    table.add_row("ntfy.topic", ntfy.get("topic", ""))

    min_sev = cfg.get("notifications", {}).get("min_severity", "warning")
    table.add_row("notifications.min_severity", min_sev)

    checks = cfg.get("checks", {})
    check_names = [
        "system", "docker", "http", "nginx", "smart", "dns", "ping",
        "home_assistant", "systemd", "process", "command", "network", "updates",
    ]
    for name in check_names:
        enabled = checks.get(name, {}).get("enabled", False)
        table.add_row(f"checks.{name}", "enabled" if enabled else "disabled")

    endpoints = checks.get("http", {}).get("endpoints", [])
    if endpoints:
        names = ", ".join(ep.get("name", "?") for ep in endpoints)
        table.add_row("http.endpoints", names)

    compose_dirs = cfg.get("update", {}).get("compose_dirs", [])
    table.add_row("update.compose_dirs", ", ".join(compose_dirs) if compose_dirs else "(none)")

    console.print(table)


@cli.command("check")
@click.option("--only", default=None, help="Comma-separated list of check modules.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--no-notify", is_flag=True, help="Run checks without sending notifications.")
@click.pass_context
def check_cmd(ctx, only, as_json, no_notify):
    """Run monitoring checks."""
    from labwatch.runner import Runner

    console = _get_console(ctx)
    cfg = _get_config(ctx)
    quiet = ctx.obj.get("quiet", False)

    modules = [m.strip() for m in only.split(",")] if only else None
    _validate_modules(modules, ctx)

    runner = Runner(cfg, verbose=ctx.obj.get("verbose", False))
    report = runner.run(modules)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
    elif not (quiet and not report.has_failures):
        table = Table(title=f"labwatch \u2014 {report.hostname}")
        table.add_column("Check", style="cyan")
        table.add_column("Status")
        table.add_column("Message")

        for result in report.results:
            table.add_row(result.name, result.severity.icon, result.message)

        console.print(table)

    if report.has_failures and not no_notify:
        runner.notify(report)
        if ctx.obj.get("verbose"):
            console.print("[dim]Notifications sent.[/dim]")

    # Exit code: 0 = OK, 1 = WARNING, 2 = CRITICAL
    if report.worst_severity == Severity.CRITICAL:
        raise SystemExit(2)
    elif report.worst_severity == Severity.WARNING:
        raise SystemExit(1)


@cli.command("notify")
@click.argument("title")
@click.argument("message")
@click.pass_context
def notify_cmd(ctx, title, message):
    """Send a one-off notification."""
    from labwatch.notifications import get_notifiers

    cfg = _get_config(ctx)
    console = _get_console(ctx)
    notifiers = get_notifiers(cfg)

    if not notifiers:
        console.print("[yellow]No notifiers configured or enabled.[/yellow]")
        raise SystemExit(1)

    for notifier in notifiers:
        try:
            notifier.send(title, message)
            console.print(f"[green]\u2714[/green] Sent via {notifier.name}")
        except Exception as e:
            console.print(f"[red]\u2718[/red] {notifier.name}: {e}")


@cli.command("discover")
@click.option("--systemd", "show_systemd", is_flag=True,
              help="Show systemd services instead of Docker containers.")
@click.pass_context
def discover_cmd(ctx, show_systemd):
    """Discover Docker containers and systemd services."""
    console = _get_console(ctx)

    if show_systemd:
        from labwatch.discovery import discover_systemd_units

        units = discover_systemd_units()
        if units is None:
            console.print("[yellow]systemctl is not available.[/yellow]")
            return

        if not units:
            console.print("[dim]No services found.[/dim]")
            return

        table = Table(title="Systemd Services")
        table.add_column("Unit", style="cyan")
        table.add_column("State")
        table.add_column("Known As")

        for u in units:
            state_style = {
                "active": "[green]active[/green]",
                "inactive": "[dim]inactive[/dim]",
                "failed": "[red]failed[/red]",
            }.get(u["state"], u["state"])
            table.add_row(
                u["unit"].replace(".service", ""),
                state_style,
                u["label"] or "[dim]-[/dim]",
            )

        console.print(table)
        return

    from labwatch.discovery import discover_containers, suggest_endpoints

    containers = discover_containers()
    if containers is None:
        console.print("[yellow]Docker is not available.[/yellow]")
        return

    if not containers:
        console.print("[dim]No containers found.[/dim]")
        return

    table = Table(title="Docker Containers")
    table.add_column("Name", style="cyan")
    table.add_column("Image")
    table.add_column("Status")

    for c in containers:
        table.add_row(c["name"], c["image"], c["status"])

    console.print(table)
    console.print()

    suggestions = suggest_endpoints(containers)
    if suggestions:
        console.print("[bold]Suggested HTTP endpoints:[/bold]")
        for s in suggestions:
            console.print(f"  {s['name']}: {s['url']}")


@cli.command("docker-update")
@click.option("--force", is_flag=True, help="Update even pinned/versioned tags.")
@click.option("--dry-run", is_flag=True, help="Show what would be updated without pulling.")
@click.pass_context
def docker_update_cmd(ctx, force, dry_run):
    """Pull latest images and restart Docker Compose services."""
    from labwatch.updater import ComposeUpdater

    console = _get_console(ctx)
    cfg = _get_config(ctx)

    compose_dirs = cfg.get("update", {}).get("compose_dirs", [])
    if not compose_dirs:
        console.print(
            "[red]No compose directories configured.[/red]\n"
            "Add them to your config under update.compose_dirs, "
            "or run [bold]labwatch init[/bold]."
        )
        raise SystemExit(1)

    if dry_run:
        console.print("[dim]Dry run — no changes will be made.[/dim]")

    updater = ComposeUpdater(cfg, force=force, dry_run=dry_run)
    results = updater.run()

    table = Table(title="Docker Compose Update")
    table.add_column("Directory", style="cyan")
    table.add_column("Pulled")
    table.add_column("Updated")
    table.add_column("Skipped")
    table.add_column("Status")

    for r in results:
        if r.error:
            status = f"[red]{r.error}[/red]"
        elif r.services_updated:
            status = "[green]updated[/green]"
        elif r.services_pulled:
            status = "[dim]no changes[/dim]"
        else:
            status = "[dim]all skipped[/dim]"

        table.add_row(
            r.directory,
            ", ".join(r.services_pulled) or "-",
            ", ".join(r.services_updated) or "-",
            ", ".join(r.services_skipped) or "-",
            status,
        )

    console.print(table)

    if not dry_run:
        updater.notify(results)
        if ctx.obj.get("verbose"):
            console.print("[dim]Notifications sent.[/dim]")


@cli.group("schedule")
def schedule_group():
    """Manage labwatch cron schedule entries."""
    pass


@schedule_group.command("check")
@click.option("--every", required=True, help="Interval (e.g. 5m, 4h, 1d).")
@click.option("--only", default=None, help="Comma-separated check modules to schedule.")
@click.pass_context
def schedule_check(ctx, every, only):
    """Schedule periodic checks via cron.

    Use --only to schedule specific modules at their own interval.
    Multiple --only entries coexist in cron, so you can run different
    checks at different frequencies.
    """
    from labwatch import scheduler

    console = _get_console(ctx)
    modules = [m.strip() for m in only.split(",")] if only else None
    _validate_modules(modules, ctx)
    try:
        line = scheduler.add_entry("check", every, modules=modules)
        console.print(f"[green]\u2714[/green] Scheduled: {line}")
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)


@schedule_group.command("docker-update")
@click.option("--every", required=True, help="Interval (e.g. 4h, 1d).")
@click.pass_context
def schedule_docker_update(ctx, every):
    """Schedule periodic Docker Compose updates via cron."""
    from labwatch import scheduler

    console = _get_console(ctx)
    try:
        line = scheduler.add_entry("docker-update", every)
        console.print(f"[green]\u2714[/green] Scheduled: {line}")
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)


@schedule_group.command("update")
@click.option("--every", required=True, help="Interval (e.g. 1d, 1w).")
@click.pass_context
def schedule_update(ctx, every):
    """Schedule automatic labwatch self-updates via cron."""
    from labwatch import scheduler

    console = _get_console(ctx)
    try:
        line = scheduler.add_entry("update", every)
        console.print(f"[green]\u2714[/green] Scheduled: {line}")
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)


@schedule_group.command("list")
@click.pass_context
def schedule_list(ctx):
    """Show all labwatch cron entries."""
    from labwatch import scheduler

    console = _get_console(ctx)
    try:
        entries = scheduler.list_entries()
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)

    if not entries:
        console.print("[dim]No labwatch cron entries found.[/dim]")
        return

    for entry in entries:
        console.print(entry)


@schedule_group.command("remove")
@click.option("--only", default=None, help="Only remove a specific subcommand (check, docker-update, update).")
@click.pass_context
def schedule_remove(ctx, only):
    """Remove labwatch cron entries."""
    from labwatch import scheduler

    console = _get_console(ctx)
    try:
        removed = scheduler.remove_entries(only)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)

    if removed:
        label = f"'{only}'" if only else "all"
        console.print(f"[green]\u2714[/green] Removed {removed} {label} labwatch cron entry(ies).")
    else:
        console.print("[dim]No matching labwatch cron entries found.[/dim]")


@cli.command("summarize")
@click.pass_context
def summarize_cmd(ctx):
    """Print a plain-English overview of what labwatch is monitoring."""
    cfg = _get_config(ctx)
    lines = _build_summary(cfg)
    for line in lines:
        click.echo(line)


def _build_summary(cfg: dict) -> list:
    """Turn the loaded config into a list of human-readable lines."""
    lines = []
    hostname = cfg.get("hostname", "unknown")
    lines.append(f"Server: {hostname}")
    lines.append("")

    # --- Notifications -----------------------------------------------------------
    notif = cfg.get("notifications", {})
    ntfy = notif.get("ntfy", {})
    min_sev = notif.get("min_severity", "warning")

    if ntfy.get("enabled"):
        server = ntfy.get("server", "https://ntfy.sh")
        topic = ntfy.get("topic", "homelab_alerts")
        lines.append(f"Notifications: ntfy enabled")
        lines.append(f"  Push to {server}/{topic}")
        lines.append(f"  Priority mapping: CRITICAL -> urgent, WARNING -> high")
        lines.append(f"  Only notify on severity >= {min_sev}")
    else:
        lines.append("Notifications: disabled (ntfy not enabled)")

    lines.append("")

    # --- Checks ------------------------------------------------------------------
    checks = cfg.get("checks", {})
    enabled_checks = []

    # System
    sys_cfg = checks.get("system", {})
    if sys_cfg.get("enabled"):
        t = sys_cfg.get("thresholds", {})
        parts = []
        parts.append(f"disk warn {t.get('disk_warning', 80)}%/crit {t.get('disk_critical', 90)}%")
        parts.append(f"mem warn {t.get('memory_warning', 80)}%/crit {t.get('memory_critical', 90)}%")
        parts.append(f"cpu warn {t.get('cpu_warning', 80)}%/crit {t.get('cpu_critical', 95)}%")
        enabled_checks.append(("System", parts))

    # Docker
    docker_cfg = checks.get("docker", {})
    if docker_cfg.get("enabled"):
        parts = []
        containers = docker_cfg.get("containers", [])
        if containers:
            parts.append(f"watching containers: {', '.join(containers)}")
        else:
            parts.append("watching all containers")
        if docker_cfg.get("watch_stopped"):
            parts.append("alerting on stopped containers")
        enabled_checks.append(("Docker", parts))

    # HTTP
    http_cfg = checks.get("http", {})
    if http_cfg.get("enabled"):
        eps = http_cfg.get("endpoints", [])
        if eps:
            parts = [f"{ep.get('name', '?')} -> {ep.get('url', '?')}" for ep in eps]
        else:
            parts = ["(no endpoints configured)"]
        enabled_checks.append(("HTTP endpoints", parts))

    # Nginx
    nginx_cfg = checks.get("nginx", {})
    if nginx_cfg.get("enabled"):
        parts = []
        container = nginx_cfg.get("container", "")
        if container:
            parts.append(f"via Docker container '{container}'")
        else:
            parts.append("via host systemd/process")
        eps = nginx_cfg.get("endpoints", [])
        if eps:
            for url in eps:
                parts.append(f"endpoint: {url}")
        enabled_checks.append(("Nginx", parts))

    # DNS
    dns_cfg = checks.get("dns", {})
    if dns_cfg.get("enabled"):
        domains = dns_cfg.get("domains", [])
        if domains:
            parts = [f"resolving: {d}" for d in domains]
        else:
            parts = ["(no domains configured)"]
        enabled_checks.append(("DNS resolution", parts))

    # Certs
    certs_cfg = checks.get("certs", {})
    if certs_cfg.get("enabled"):
        domains = certs_cfg.get("domains", [])
        warn_d = certs_cfg.get("warn_days", 14)
        crit_d = certs_cfg.get("critical_days", 7)
        if domains:
            parts = [f"checking: {d}" for d in domains]
        else:
            parts = ["(no domains configured)"]
        parts.append(f"warn at {warn_d} days, critical at {crit_d} days")
        enabled_checks.append(("TLS certificates", parts))

    # Ping
    ping_cfg = checks.get("ping", {})
    if ping_cfg.get("enabled"):
        hosts = ping_cfg.get("hosts", [])
        timeout = ping_cfg.get("timeout", 5)
        if hosts:
            parts = [f"pinging: {h}" for h in hosts]
        else:
            parts = ["(no hosts configured)"]
        parts.append(f"timeout: {timeout}s")
        enabled_checks.append(("Ping", parts))

    # Network
    net_cfg = checks.get("network", {})
    if net_cfg.get("enabled"):
        ifaces = net_cfg.get("interfaces", [])
        if ifaces:
            parts = [f"{i.get('name', '?')} ({i.get('severity', 'critical')})" for i in ifaces]
        else:
            parts = ["(no interfaces configured)"]
        enabled_checks.append(("Network interfaces", parts))

    # Home Assistant
    ha_cfg = checks.get("home_assistant", {})
    if ha_cfg.get("enabled"):
        parts = [f"URL: {ha_cfg.get('url', '?')}"]
        ext = ha_cfg.get("external_url", "")
        if ext:
            parts.append(f"external URL: {ext}")
        if ha_cfg.get("token"):
            parts.append("authenticated (token set)")
        else:
            parts.append("unauthenticated (no token)")
        if ha_cfg.get("google_home"):
            parts.append("Google Home connectivity check enabled")
        enabled_checks.append(("Home Assistant", parts))

    # Systemd
    sd_cfg = checks.get("systemd", {})
    if sd_cfg.get("enabled"):
        units = sd_cfg.get("units", [])
        parts = []
        for u in units:
            if isinstance(u, str):
                parts.append(f"{u} (critical)")
            else:
                name = u.get("name", "?")
                sev = u.get("severity", "critical")
                parts.append(f"{name} ({sev})")
        if not parts:
            parts = ["(no units configured)"]
        enabled_checks.append(("Systemd units", parts))

    # Process
    proc_cfg = checks.get("process", {})
    if proc_cfg.get("enabled"):
        names = proc_cfg.get("names", [])
        if names:
            parts = [name for name in names]
        else:
            parts = ["(no process names configured)"]
        enabled_checks.append(("Processes", parts))

    # Command
    cmd_cfg = checks.get("command", {})
    if cmd_cfg.get("enabled"):
        cmds = cmd_cfg.get("commands", [])
        parts = []
        for c in cmds:
            desc = f"{c.get('name', '?')}: `{c.get('command', '?')}`"
            extras = []
            if c.get("expect_output"):
                extras.append(f"expect '{c['expect_output']}' in output")
            if c.get("expect_exit") is not None and c["expect_exit"] != 0:
                extras.append(f"expect exit {c['expect_exit']}")
            sev = c.get("severity", "critical")
            if sev != "critical":
                extras.append(f"severity: {sev}")
            if extras:
                desc += f" ({', '.join(extras)})"
            parts.append(desc)
        if not parts:
            parts = ["(no commands configured)"]
        enabled_checks.append(("Custom commands", parts))

    # Updates
    upd_cfg = checks.get("updates", {})
    if upd_cfg.get("enabled"):
        warn_t = upd_cfg.get("warning_threshold", 1)
        crit_t = upd_cfg.get("critical_threshold", 50)
        parts = [
            f"warn at {warn_t}+ pending, critical at {crit_t}+",
        ]
        enabled_checks.append(("System updates", parts))

    # S.M.A.R.T.
    smart_cfg = checks.get("smart", {})
    if smart_cfg.get("enabled"):
        parts = [
            f"temp warn {smart_cfg.get('temp_warning', 50)}C/crit {smart_cfg.get('temp_critical', 60)}C",
            f"wear warn {smart_cfg.get('wear_warning', 80)}%/crit {smart_cfg.get('wear_critical', 90)}%",
        ]
        devices = smart_cfg.get("devices", [])
        if devices:
            parts.append(f"devices: {', '.join(devices)}")
        else:
            parts.append("auto-detect all devices")
        enabled_checks.append(("S.M.A.R.T. disk health", parts))

    # --- Render ------------------------------------------------------------------
    if enabled_checks:
        lines.append(f"Monitoring ({len(enabled_checks)} check groups enabled):")
        for label, parts in enabled_checks:
            lines.append(f"  {label}:")
            for p in parts:
                lines.append(f"    - {p}")
    else:
        lines.append("No checks are currently enabled.")

    # Disabled checks
    all_names = {
        "system": "System", "docker": "Docker", "http": "HTTP",
        "nginx": "Nginx", "smart": "S.M.A.R.T.", "dns": "DNS",
        "certs": "Certs", "ping": "Ping",
        "network": "Network", "home_assistant": "Home Assistant",
        "systemd": "Systemd", "process": "Process", "command": "Command",
        "updates": "Updates",
    }
    disabled = [
        label for key, label in all_names.items()
        if not checks.get(key, {}).get("enabled")
    ]
    if disabled:
        lines.append("")
        lines.append(f"Disabled: {', '.join(disabled)}")

    # Auto-updates
    compose_dirs = cfg.get("update", {}).get("compose_dirs", [])
    if compose_dirs:
        lines.append("")
        lines.append("Docker Compose auto-update directories:")
        for d in compose_dirs:
            lines.append(f"  - {d}")

    return lines


@cli.command("motd")
@click.option("--only", default=None, help="Comma-separated list of check modules.")
@click.pass_context
def motd_cmd(ctx, only):
    """Print a plain-text login summary for use as an SSH MOTD.

    Add a script to /etc/profile.d/ or /etc/update-motd.d/ that calls
    this command so you see system status every time you log in.
    """
    from labwatch.runner import Runner

    cfg = _get_config(ctx)
    modules = [m.strip() for m in only.split(",")] if only else None
    _validate_modules(modules, ctx)
    runner = Runner(cfg, verbose=False)
    report = runner.run(modules)

    _ICONS = {"ok": "+", "warning": "!", "critical": "X", "unknown": "?"}

    hostname = report.hostname
    failures = [r for r in report.results if r.severity in (
        Severity.WARNING, Severity.CRITICAL,
    )]

    click.echo(f"--- labwatch | {hostname} ---")

    if not report.results:
        click.echo("  No checks ran.")
        return

    for result in report.results:
        icon = _ICONS.get(result.severity.value, "?")
        click.echo(f"  [{icon}] {result.name}: {result.message}")

    if not failures:
        click.echo("  All checks passed.")


@cli.command("init")
@click.option("--only", default=None,
              help="Comma-separated wizard sections to run (requires existing config).")
@click.pass_context
def init_cmd(ctx, only):
    """Interactive setup wizard."""
    from labwatch.wizard import run_wizard

    config_path = ctx.obj.get("config_path")
    if config_path:
        config_path = Path(config_path)
    run_wizard(config_path, only=only)


@cli.command("enable")
@click.argument("module")
@click.pass_context
def enable_cmd(ctx, module):
    """Enable a check module.

    \b
    Example:
      labwatch enable docker
      labwatch enable dns
    """
    _toggle_module(ctx, module, True)


@cli.command("disable")
@click.argument("module")
@click.pass_context
def disable_cmd(ctx, module):
    """Disable a check module.

    \b
    Example:
      labwatch disable docker
      labwatch disable dns
    """
    _toggle_module(ctx, module, False)


def _toggle_module(ctx, module: str, enabled: bool) -> None:
    """Toggle a check module on or off and save config."""
    from labwatch.config import save_config

    console = _get_console(ctx)
    _validate_modules([module], ctx)

    config_path = ctx.obj.get("config_path")
    path = Path(config_path) if config_path else default_config_path()
    if not path.exists():
        console.print("[red]No config file found.[/red] Run [bold]labwatch init[/bold] first.")
        raise SystemExit(1)

    cfg = _get_config(ctx)
    cfg.setdefault("checks", {}).setdefault(module, {})["enabled"] = enabled
    save_config(cfg, path)

    state = "enabled" if enabled else "disabled"
    console.print(f"[green]\u2714[/green] {module} {state}")


@cli.command("update")
@click.pass_context
def update_cmd(ctx):
    """Update labwatch to the latest version from PyPI."""
    console = _get_console(ctx)
    current = __version__

    console.print(f"[bold]Current version:[/bold] {current}")
    console.print("Checking PyPI for updates...")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "labwatch"],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        console.print(f"[red]Update failed:[/red]")
        if result.stderr:
            console.print(result.stderr.strip())
        raise SystemExit(1)

    # Re-check the installed version
    ver_result = subprocess.run(
        [sys.executable, "-c", "import labwatch; print(labwatch.__version__)"],
        capture_output=True, text=True,
    )
    new_version = ver_result.stdout.strip() if ver_result.returncode == 0 else "unknown"

    if new_version == current:
        console.print(f"[green]\u2714[/green] Already up to date ({current})")
    else:
        console.print(f"[green]\u2714[/green] Updated: {current} \u2192 {new_version}")


@cli.command("doctor")
@click.pass_context
def doctor_cmd(ctx):
    """Check labwatch installation health.

    Verifies config, connectivity, required tools, and cron entries.
    """
    console = _get_console(ctx)
    ok_count = 0
    warn_count = 0
    fail_count = 0

    def _ok(msg):
        nonlocal ok_count
        ok_count += 1
        console.print(f"  [green]\u2714[/green] {msg}")

    def _warn(msg):
        nonlocal warn_count
        warn_count += 1
        console.print(f"  [yellow]\u26a0[/yellow] {msg}")

    def _fail(msg):
        nonlocal fail_count
        fail_count += 1
        console.print(f"  [red]\u2718[/red] {msg}")

    console.print("[bold]labwatch doctor[/bold]")
    console.print()

    # --- Config file ---
    console.print("[bold]Config[/bold]")
    config_path_str = ctx.obj.get("config_path")
    path = Path(config_path_str) if config_path_str else default_config_path()
    if path.exists():
        _ok(f"Config file exists: {path}")
        # Check permissions on Unix
        if sys.platform != "win32":
            mode = oct(path.stat().st_mode)[-3:]
            if mode in ("600", "400", "640", "644"):
                _ok(f"File permissions: {mode}")
            else:
                _warn(f"File permissions are {mode} — consider chmod 600 to protect secrets")
    else:
        _fail(f"Config file not found: {path}")
        console.print("    Run [bold]labwatch init[/bold] to create it.")
        console.print()
        console.print(f"  {ok_count} passed, {warn_count} warnings, {fail_count} errors")
        raise SystemExit(1)

    cfg = _get_config(ctx)
    errors = validate_config(cfg)
    if errors:
        _fail(f"Config validation failed ({len(errors)} error(s))")
        for err in errors:
            console.print(f"    {err}")
    else:
        _ok("Config is valid")

    # Check for unexpanded env vars
    import yaml as _yaml
    with open(path, "r") as f:
        raw = f.read()
    unexpanded = [m.group(0) for m in __import__("re").finditer(r"\$\{(\w+)\}", raw)
                  if not os.environ.get(m.group(1))]
    if unexpanded:
        _warn(f"Unexpanded env vars (not set): {', '.join(unexpanded)}")

    console.print()

    # --- Notifications ---
    console.print("[bold]Notifications[/bold]")
    ntfy = cfg.get("notifications", {}).get("ntfy", {})
    if ntfy.get("enabled"):
        server = ntfy.get("server", "")
        topic = ntfy.get("topic", "")
        if server and topic:
            _ok(f"ntfy configured: {server}/{topic}")
            # Test connectivity to server
            try:
                import requests
                resp = requests.get(server, timeout=5)
                if resp.status_code < 500:
                    _ok(f"ntfy server reachable ({resp.status_code})")
                else:
                    _warn(f"ntfy server returned {resp.status_code}")
            except Exception as e:
                _fail(f"Cannot reach ntfy server: {e}")
        else:
            _fail("ntfy enabled but server/topic not configured")
    else:
        _warn("No notification backend enabled")

    console.print()

    # --- Docker ---
    console.print("[bold]Docker[/bold]")
    docker_enabled = cfg.get("checks", {}).get("docker", {}).get("enabled", False)
    if docker_enabled:
        try:
            import docker as _docker
            client = _docker.from_env()
            client.ping()
            _ok("Docker daemon reachable")
        except Exception as e:
            _fail(f"Docker daemon not reachable: {e}")
    else:
        console.print("  [dim]Docker check disabled — skipped[/dim]")

    console.print()

    # --- System tools ---
    console.print("[bold]System tools[/bold]")
    checks_cfg = cfg.get("checks", {})

    tool_checks = []
    if checks_cfg.get("systemd", {}).get("enabled"):
        tool_checks.append(("systemctl", "systemd"))
    if checks_cfg.get("process", {}).get("enabled") and sys.platform != "win32":
        tool_checks.append(("pgrep", "process"))
    if checks_cfg.get("ping", {}).get("enabled"):
        tool_checks.append(("ping", "ping"))
    if checks_cfg.get("network", {}).get("enabled"):
        tool_checks.append(("ip", "network"))
    if checks_cfg.get("smart", {}).get("enabled"):
        tool_checks.append(("smartctl", "smart"))

    if tool_checks:
        import shutil
        for tool, check_name in tool_checks:
            if shutil.which(tool):
                _ok(f"{tool} found (used by {check_name} check)")
            else:
                _fail(f"{tool} not found — required by {check_name} check")
    else:
        console.print("  [dim]No tool-dependent checks enabled[/dim]")

    console.print()

    # --- Cron ---
    console.print("[bold]Schedule[/bold]")
    if sys.platform == "win32":
        console.print("  [dim]Cron not available on Windows — use Task Scheduler[/dim]")
    else:
        try:
            from labwatch.scheduler import list_entries
            entries = list_entries()
            if entries:
                _ok(f"{len(entries)} cron entry(ies) installed")
                for entry in entries:
                    console.print(f"    {entry}")
            else:
                _warn("No labwatch cron entries found — checks won't run automatically")
                console.print("    Run [bold]labwatch init[/bold] or [bold]labwatch schedule check --every 5m[/bold]")
        except Exception as e:
            _warn(f"Could not read crontab: {e}")

    console.print()
    console.print(f"  {ok_count} passed, {warn_count} warnings, {fail_count} errors")

    if fail_count:
        raise SystemExit(1)
