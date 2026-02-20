"""CLI entry point for labwatch."""

import io
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

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


@cli.command("check")
@click.option("--only", default=None, help="Comma-separated list of check modules.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--no-notify", is_flag=True, help="Run checks without sending notifications.")
@click.pass_context
def check_cmd(ctx, only, as_json, no_notify):
    """Run monitoring checks."""
    import logging
    from labwatch.heartbeat import ping_heartbeat
    from labwatch.lock import Lock
    from labwatch.logging_setup import setup_logging
    from labwatch.runner import Runner

    logger = setup_logging()
    lock = Lock()
    if not lock.acquire():
        logging.getLogger("labwatch").warning("check skipped: another instance is running")
        return

    try:
        console = _get_console(ctx)
        cfg = _get_config(ctx)
        quiet = ctx.obj.get("quiet", False)

        modules = [m.strip() for m in only.split(",")] if only else None
        _validate_modules(modules, ctx)

        logger.info("check started")
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
            logger.info("notifications sent for %d failure(s)",
                        sum(1 for r in report.results
                            if r.severity in (Severity.WARNING, Severity.CRITICAL)))

        ok_count = sum(1 for r in report.results if r.severity == Severity.OK)
        fail_count = len(report.results) - ok_count
        logger.info("check complete: %d ok, %d failed, worst=%s",
                     ok_count, fail_count, report.worst_severity.value)

        ping_heartbeat(cfg, report.has_failures)

        # Exit code: 0 = OK, 1 = WARNING, 2 = CRITICAL
        if report.worst_severity == Severity.CRITICAL:
            raise SystemExit(2)
        elif report.worst_severity == Severity.WARNING:
            raise SystemExit(1)
    finally:
        lock.release()


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
    import logging
    from labwatch.lock import Lock
    from labwatch.logging_setup import setup_logging
    from labwatch.updater import ComposeUpdater

    logger = setup_logging()
    lock = Lock()
    if not lock.acquire():
        logging.getLogger("labwatch").warning("docker-update skipped: another instance is running")
        return

    try:
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

        logger.info("docker-update complete")
    finally:
        lock.release()


@cli.command("system-update")
@click.option("--dry-run", is_flag=True, help="Show upgradable packages without installing.")
@click.pass_context
def system_update_cmd(ctx, dry_run):
    """Run apt-get upgrade on Debian/DietPi systems."""
    import logging
    from labwatch.lock import Lock
    from labwatch.logging_setup import setup_logging
    from labwatch.system_updater import SystemUpdater

    logger = setup_logging()
    lock = Lock()
    if not lock.acquire():
        logging.getLogger("labwatch").warning("system-update skipped: another instance is running")
        return

    try:
        console = _get_console(ctx)
        cfg = _get_config(ctx)

        sys_cfg = cfg.get("update", {}).get("system", {})
        if not sys_cfg.get("enabled"):
            console.print(
                "[red]System updates are not enabled.[/red]\n"
                "Enable them in your config under update.system.enabled, "
                "or run [bold]labwatch init[/bold]."
            )
            raise SystemExit(1)

        if dry_run:
            console.print("[dim]Dry run — no changes will be made.[/dim]")

        updater = SystemUpdater(cfg, dry_run=dry_run)
        result = updater.run()

        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
            updater.notify(result)
            raise SystemExit(1)

        if result.dry_run:
            if result.packages_upgraded:
                console.print(f"[bold]{len(result.packages_upgraded)} package(s) upgradable:[/bold]")
                for pkg in result.packages_upgraded:
                    console.print(f"  {pkg}")
            else:
                console.print("[green]System is up to date.[/green]")
            logger.info("system-update complete (dry-run)")
            return

        if result.packages_upgraded:
            console.print(f"[green]\u2714[/green] {len(result.packages_upgraded)} package(s) upgraded")
        else:
            console.print("[green]\u2714[/green] System is up to date")

        if result.packages_removed:
            console.print(f"  {len(result.packages_removed)} package(s) auto-removed")

        if result.rebooting:
            console.print("[yellow]Reboot scheduled in 1 minute.[/yellow]")
        elif result.reboot_required:
            console.print("[yellow]Reboot required.[/yellow]")

        updater.notify(result)
        if ctx.obj.get("verbose"):
            console.print("[dim]Notifications sent.[/dim]")

        logger.info("system-update complete")

        if result.rebooting:
            updater.do_reboot()
    finally:
        lock.release()


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


@schedule_group.command("system-update")
@click.option("--every", required=True, help="Interval (e.g. 1d, 1w).")
@click.pass_context
def schedule_system_update(ctx, every):
    """Schedule periodic system package updates via cron."""
    from labwatch import scheduler

    console = _get_console(ctx)
    try:
        line = scheduler.add_entry("system-update", every)
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
    """Show a Rich tree overview of the current configuration."""
    console = _get_console(ctx)
    config_path = ctx.obj.get("config_path")
    resolved_path = Path(config_path) if config_path else default_config_path()
    cfg = _get_config(ctx)
    console.print(f"[bold]Config file:[/bold] {resolved_path}")
    console.print()
    tree = _build_config_tree(cfg)
    console.print(tree)


@cli.command("validate")
@click.pass_context
def validate_cmd(ctx):
    """Validate the config file."""
    console = _get_console(ctx)
    config_path = ctx.obj.get("config_path")
    resolved_path = Path(config_path) if config_path else default_config_path()
    cfg = _get_config(ctx)
    errors = validate_config(cfg)
    if errors:
        console.print("[red]Config validation failed:[/red]")
        for err in errors:
            console.print(f"  [red]\u2718[/red] {err}")
        raise SystemExit(1)
    else:
        console.print(f"[green]\u2714[/green] Config is valid: {resolved_path}")


@cli.command("edit")
@click.pass_context
def edit_cmd(ctx):
    """Open the config file in your default editor."""
    console = _get_console(ctx)
    config_path = ctx.obj.get("config_path")
    resolved_path = Path(config_path) if config_path else default_config_path()
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


# ---------------------------------------------------------------------------
# Rich config tree — used by the `summarize` command
# ---------------------------------------------------------------------------

_MODULE_DISPLAY = [
    ("system", "System"),
    ("docker", "Docker"),
    ("http", "HTTP Endpoints"),
    ("nginx", "Nginx"),
    ("smart", "S.M.A.R.T."),
    ("dns", "DNS Resolution"),
    ("certs", "TLS Certificates"),
    ("ping", "Ping"),
    ("network", "Network Interfaces"),
    ("home_assistant", "Home Assistant"),
    ("systemd", "Systemd Units"),
    ("process", "Processes"),
    ("updates", "Package Updates"),
    ("command", "Custom Commands"),
]


def _build_config_tree(cfg: dict) -> Tree:
    """Build a Rich Tree representing the full configuration."""
    hostname = cfg.get("hostname", "unknown")
    tree = Tree(f"[bold cyan]{hostname}[/bold cyan]")

    # --- Notifications ---
    notif = cfg.get("notifications", {})
    ntfy = notif.get("ntfy", {})
    if ntfy.get("enabled"):
        server = ntfy.get("server", "https://ntfy.sh")
        topic = ntfy.get("topic", "homelab_alerts")
        notif_branch = tree.add("[green]Notifications enabled[/green]")
        notif_branch.add(f"ntfy: {server}/{topic}")
        min_sev = notif.get("min_severity", "warning")
        notif_branch.add(f"min severity: {min_sev}")
    else:
        tree.add("[dim]Notifications disabled[/dim]")

    # --- Monitoring modules ---
    checks = cfg.get("checks", {})
    enabled_modules = []
    disabled_modules = []
    for key, label in _MODULE_DISPLAY:
        if checks.get(key, {}).get("enabled"):
            enabled_modules.append((key, label))
        else:
            disabled_modules.append(label)

    if enabled_modules:
        mon_branch = tree.add(f"[bold]Monitoring ({len(enabled_modules)} modules)[/bold]")
        _tree_builders = {
            "system": _tree_system,
            "docker": _tree_docker,
            "http": _tree_http,
            "nginx": _tree_nginx,
            "smart": _tree_smart,
            "dns": _tree_dns,
            "certs": _tree_certs,
            "ping": _tree_ping,
            "network": _tree_network,
            "home_assistant": _tree_home_assistant,
            "systemd": _tree_systemd,
            "process": _tree_process,
            "updates": _tree_updates,
            "command": _tree_command,
        }
        for key, label in enabled_modules:
            mod_branch = mon_branch.add(f"[cyan]{label}[/cyan]")
            builder = _tree_builders.get(key)
            if builder:
                builder(mod_branch, checks.get(key, {}))
    else:
        tree.add("[dim]No checks enabled[/dim]")

    # --- Disabled modules ---
    if disabled_modules:
        tree.add(f"[dim]Disabled: {', '.join(disabled_modules)}[/dim]")

    # --- Docker auto-updates ---
    compose_dirs = cfg.get("update", {}).get("compose_dirs", [])
    if compose_dirs:
        upd_branch = tree.add(f"[bold]Docker auto-updates ({len(compose_dirs)} directories)[/bold]")
        for d in compose_dirs:
            upd_branch.add(d)

    # --- System updates ---
    system_update = cfg.get("update", {}).get("system", {})
    if system_update.get("enabled"):
        mode = system_update.get("mode", "safe")
        mode_label = "apt-get upgrade" if mode == "safe" else "apt-get dist-upgrade"
        su_branch = tree.add(f"[bold]System updates ({mode_label})[/bold]")
        su_branch.add(f"mode: {mode}")
        if system_update.get("autoremove", True):
            su_branch.add("autoremove: yes")
        if system_update.get("auto_reboot", False):
            su_branch.add("auto-reboot: enabled")

    return tree


def _tree_system(branch, cfg):
    t = cfg.get("thresholds", {})
    branch.add(f"disk: warn {t.get('disk_warning', 80)}% / crit {t.get('disk_critical', 90)}%")
    branch.add(f"memory: warn {t.get('memory_warning', 80)}% / crit {t.get('memory_critical', 90)}%")
    branch.add(f"cpu: warn {t.get('cpu_warning', 80)}% / crit {t.get('cpu_critical', 95)}%")


def _tree_docker(branch, cfg):
    containers = cfg.get("containers", [])
    if containers:
        branch.add(f"watching: {', '.join(containers)}")
    else:
        branch.add("watching: all containers")
    if cfg.get("watch_stopped"):
        branch.add("alert on stopped containers")


def _tree_http(branch, cfg):
    eps = cfg.get("endpoints", [])
    if eps:
        for ep in eps:
            timeout = ep.get("timeout", 10)
            branch.add(f"{ep.get('name', '?')}: {ep.get('url', '?')} (timeout {timeout}s)")
    else:
        branch.add("[dim](no endpoints configured)[/dim]")


def _tree_nginx(branch, cfg):
    container = cfg.get("container", "")
    if container:
        branch.add(f"via Docker container: {container}")
    else:
        branch.add("via host systemd/process")
    if cfg.get("config_test", True):
        branch.add("config test: enabled")
    eps = cfg.get("endpoints", [])
    for url in eps:
        branch.add(f"endpoint: {url}")


def _tree_smart(branch, cfg):
    branch.add(f"temp: warn {cfg.get('temp_warning', 50)}C / crit {cfg.get('temp_critical', 60)}C")
    branch.add(f"wear: warn {cfg.get('wear_warning', 80)}% / crit {cfg.get('wear_critical', 90)}%")
    devices = cfg.get("devices", [])
    if devices:
        for d in devices:
            branch.add(f"device: {d}")
    else:
        branch.add("auto-detect all devices")


def _tree_dns(branch, cfg):
    domains = cfg.get("domains", [])
    if domains:
        for d in domains:
            branch.add(d)
    else:
        branch.add("[dim](no domains configured)[/dim]")


def _tree_certs(branch, cfg):
    domains = cfg.get("domains", [])
    if domains:
        for d in domains:
            branch.add(d)
    else:
        branch.add("[dim](no domains configured)[/dim]")
    warn_d = cfg.get("warn_days", 14)
    crit_d = cfg.get("critical_days", 7)
    branch.add(f"warn at {warn_d} days / crit at {crit_d} days")


def _tree_ping(branch, cfg):
    hosts = cfg.get("hosts", [])
    if hosts:
        for h in hosts:
            branch.add(h)
    else:
        branch.add("[dim](no hosts configured)[/dim]")
    branch.add(f"timeout: {cfg.get('timeout', 5)}s")


def _tree_network(branch, cfg):
    ifaces = cfg.get("interfaces", [])
    if ifaces:
        for i in ifaces:
            branch.add(f"{i.get('name', '?')} ({i.get('severity', 'critical')})")
    else:
        branch.add("[dim](no interfaces configured)[/dim]")


def _tree_home_assistant(branch, cfg):
    branch.add(f"URL: {cfg.get('url', '?')}")
    ext = cfg.get("external_url", "")
    if ext:
        branch.add(f"external: {ext}")
    if cfg.get("token"):
        branch.add("token: set")
    else:
        branch.add("token: not set")
    if cfg.get("google_home"):
        branch.add("Google Home check: enabled")


def _tree_systemd(branch, cfg):
    units = cfg.get("units", [])
    if units:
        for u in units:
            if isinstance(u, str):
                branch.add(f"{u} (critical)")
            else:
                branch.add(f"{u.get('name', '?')} ({u.get('severity', 'critical')})")
    else:
        branch.add("[dim](no units configured)[/dim]")


def _tree_process(branch, cfg):
    names = cfg.get("names", [])
    if names:
        for n in names:
            branch.add(n)
    else:
        branch.add("[dim](no process names configured)[/dim]")


def _tree_updates(branch, cfg):
    warn_t = cfg.get("warning_threshold", 1)
    crit_t = cfg.get("critical_threshold", 50)
    branch.add(f"warn at {warn_t}+ pending")
    branch.add(f"critical at {crit_t}+ pending")


def _tree_command(branch, cfg):
    cmds = cfg.get("commands", [])
    if cmds:
        for c in cmds:
            name = c.get("name", "?")
            cmd = c.get("command", "?")
            sev = c.get("severity", "critical")
            desc = f"{name}: {cmd} ({sev})"
            extras = []
            if c.get("expect_output"):
                extras.append(f"expect '{c['expect_output']}'")
            if c.get("expect_exit") is not None and c["expect_exit"] != 0:
                extras.append(f"expect exit {c['expect_exit']}")
            if extras:
                desc += f" ({', '.join(extras)})"
            branch.add(desc)
    else:
        branch.add("[dim](no commands configured)[/dim]")


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


@cli.command("modules")
@click.pass_context
def modules_cmd(ctx):
    """List all available modules with descriptions and status."""
    from labwatch.wizard import MODULES

    console = _get_console(ctx)
    cfg = {}
    try:
        cfg = _get_config(ctx)
    except Exception:
        pass  # no config yet — show all as disabled

    console.print("[bold]Available modules[/bold]")
    console.print()

    for mod in MODULES:
        key = mod["key"]
        label = mod["label"]
        desc = mod["short_desc"]
        config_path = mod["config_path"]

        # Resolve enabled state from config
        if config_path.startswith("checks."):
            check_name = config_path.split(".", 1)[1]
            enabled = cfg.get("checks", {}).get(check_name, {}).get("enabled", False)
        elif config_path == "update.compose_dirs":
            enabled = bool(cfg.get("update", {}).get("compose_dirs", []))
        elif config_path == "update.system":
            enabled = cfg.get("update", {}).get("system", {}).get("enabled", False)
        else:
            enabled = False

        status = "[green]on[/green]" if enabled else "[dim]off[/dim]"
        console.print(f"  {status:>16s}  [bold]{key:18s}[/bold] {label} -- {desc}")

    console.print()
    console.print("[dim]Use 'labwatch enable <module>' / 'labwatch disable <module>' to toggle.[/dim]")
    console.print("[dim]Use 'labwatch init --only <module>' to reconfigure a module.[/dim]")


@cli.command("update")
@click.pass_context
def update_cmd(ctx):
    """Update labwatch to the latest version from PyPI."""
    console = _get_console(ctx)
    current = __version__

    console.print(f"[bold]Current version:[/bold] {current}")
    console.print("Checking for updates...")

    # Check GitHub tags for the latest version — updates instantly on push,
    # unlike PyPI's CDN which can lag by several minutes.
    latest = None
    try:
        url = "https://api.github.com/repos/rbretschneider/labwatch_cli/tags?per_page=1"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            tags = json.loads(resp.read())
        if tags:
            latest = tags[0]["name"].lstrip("v")
    except Exception:
        pass

    # Fallback to PyPI JSON API if GitHub check failed
    if not latest:
        try:
            url = "https://pypi.org/pypi/labwatch/json"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                latest = json.loads(resp.read())["info"]["version"]
        except Exception as e:
            console.print(f"[red]Failed to check for updates:[/red] {e}")
            raise SystemExit(1)

    if latest == current:
        console.print(f"[green]\u2714[/green] Already up to date ({current})")
        return

    console.print(f"Updating to {latest}...")

    # PyPI's package index may lag behind GitHub tags by a few minutes.
    # Retry with increasing delays until the package is available.
    pip_cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", f"labwatch=={latest}"]
    for attempt in range(4):
        result = subprocess.run(pip_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            break
        if "No matching distribution" in (result.stderr or "") and attempt < 3:
            wait = 5 * (attempt + 1)
            console.print(f"  Waiting for PyPI to sync ({wait}s)...")
            time.sleep(wait)
            continue
        console.print(f"[red]Update failed:[/red]")
        if result.stderr:
            console.print(result.stderr.strip())
        raise SystemExit(1)

    console.print(f"[green]\u2714[/green] Updated: {current} \u2192 {latest}")


def _verify_cron_entries(entries, console, _ok, _warn, _fail):
    """Deep-verify that installed cron entries will actually execute.

    Checks:
    1. Cron daemon is running
    2. labwatch binary path in each entry exists on disk
    3. sudo entries have passwordless NOPASSWD configured
    """
    import shutil
    from labwatch.scheduler import MARKER_PREFIX

    # --- Cron daemon ---
    cron_running = False
    if shutil.which("systemctl"):
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", "cron"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.stdout.strip() == "active":
                cron_running = True
            else:
                # Some distros name it crond
                proc2 = subprocess.run(
                    ["systemctl", "is-active", "crond"],
                    capture_output=True, text=True, timeout=5,
                )
                cron_running = proc2.stdout.strip() == "active"
        except Exception:
            pass
    if not cron_running and shutil.which("pgrep"):
        try:
            proc = subprocess.run(
                ["pgrep", "-x", "cron"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode != 0:
                proc = subprocess.run(
                    ["pgrep", "-x", "crond"],
                    capture_output=True, text=True, timeout=5,
                )
            cron_running = proc.returncode == 0
        except Exception:
            pass

    if cron_running:
        _ok("Cron daemon is running")
    else:
        _fail("Cron daemon does not appear to be running")
        console.print("    Check with: [bold]systemctl status cron[/bold]")

    # --- Per-entry checks ---
    for entry in entries:
        # Parse: strip the cron expression (first 5 fields) and marker
        parts = entry.split()
        # Cron expression is always 5 fields, then the command
        cmd_parts = parts[5:]
        # Remove the marker comment at the end
        cmd_parts = [p for p in cmd_parts if not p.startswith(MARKER_PREFIX)]

        uses_sudo = cmd_parts and cmd_parts[0] == "sudo"
        if uses_sudo:
            cmd_parts = cmd_parts[1:]

        if not cmd_parts:
            continue

        # The binary is the first token (could be a path or "python -m labwatch")
        binary = cmd_parts[0]

        # Check binary exists
        if os.path.isabs(binary):
            if os.path.isfile(binary):
                _ok(f"Binary exists: {binary}")
            else:
                _fail(f"Binary not found: {binary}")
                console.print("    labwatch may have been reinstalled to a different path")
                console.print(f"    Fix: [bold]labwatch schedule remove && labwatch schedule check --every 5m[/bold]")
        else:
            # Relative command like "python" — check it's findable
            if shutil.which(binary):
                _ok(f"Binary in PATH: {binary}")
            else:
                _warn(f"Binary not in PATH: {binary} — cron may not find it")

        # Check sudo NOPASSWD
        if uses_sudo:
            # Build the actual command that cron would run (without cron expr)
            # e.g. "sudo /usr/bin/labwatch system-update"
            sudo_cmd = " ".join(cmd_parts)
            try:
                proc = subprocess.run(
                    ["sudo", "-n", binary, "--help"],
                    capture_output=True, text=True, timeout=5,
                )
                if proc.returncode == 0:
                    _ok(f"sudo NOPASSWD works for: {binary}")
                else:
                    _fail(f"sudo requires a password for: {binary}")
                    console.print("    Cron cannot enter passwords — the job will hang/fail")
                    console.print("    Fix: [bold]sudo visudo -f /etc/sudoers.d/labwatch[/bold]")
                    import getpass
                    user = getpass.getuser()
                    console.print(f"    Add:  [bold]{user} ALL=(root) NOPASSWD: {binary} system-update[/bold]")
            except FileNotFoundError:
                _warn("sudo command not found — cannot verify NOPASSWD")
            except Exception:
                _warn(f"Could not test sudo for: {binary}")


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

    # --- PATH persistence ---
    if sys.platform != "win32":
        import shutil
        lw_bin = shutil.which("labwatch")
        if lw_bin:
            bin_dir = str(Path(lw_bin).parent)
            # Check if the directory is in a common shell profile so it
            # survives new sessions and cron.  We look at ~/.bashrc and
            # ~/.profile — the two files Debian sources for login shells.
            home = Path.home()
            profiles = [home / ".bashrc", home / ".profile", home / ".bash_profile"]
            in_default_path = bin_dir in ("/usr/bin", "/usr/local/bin", "/bin", "/sbin",
                                          "/usr/sbin", "/usr/local/sbin")
            if not in_default_path:
                found_in_profile = False
                for pf in profiles:
                    try:
                        if pf.exists() and bin_dir in pf.read_text():
                            found_in_profile = True
                            break
                    except OSError:
                        pass
                if not found_in_profile:
                    _warn(f"labwatch is in {bin_dir} which may not be in PATH for new shells")
                    console.print(f"    Add to ~/.bashrc:  [bold]export PATH=\"{bin_dir}:$PATH\"[/bold]")
                else:
                    _ok(f"labwatch binary: {lw_bin}")
            else:
                _ok(f"labwatch binary: {lw_bin}")
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

    # --- Heartbeat ---
    hb_url = cfg.get("notifications", {}).get("heartbeat_url", "")
    if hb_url:
        console.print()
        console.print("[bold]Heartbeat[/bold]")
        try:
            import requests as _requests
            resp = _requests.get(hb_url, timeout=5)
            if resp.status_code < 500:
                _ok(f"Heartbeat URL reachable ({resp.status_code})")
            else:
                _warn(f"Heartbeat URL returned {resp.status_code}")
        except Exception as e:
            _fail(f"Cannot reach heartbeat URL: {e}")

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

    # --- Logging ---
    console.print("[bold]Logging[/bold]")
    from labwatch.logging_setup import _log_path
    log_dir = _log_path().parent
    if log_dir.exists():
        if os.access(str(log_dir), os.W_OK):
            _ok(f"Log directory writable: {log_dir}")
        else:
            _fail(f"Log directory not writable: {log_dir}")
    else:
        _warn(f"Log directory does not exist yet: {log_dir} (will be created on first run)")

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

            # --- Verify cron entries will actually work ---
            if entries:
                _verify_cron_entries(entries, console, _ok, _warn, _fail)
        except Exception as e:
            _warn(f"Could not read crontab: {e}")

    console.print()
    console.print(f"  {ok_count} passed, {warn_count} warnings, {fail_count} errors")

    if fail_count:
        raise SystemExit(1)
