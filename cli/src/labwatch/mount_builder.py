"""Systemd mount-unit builder for CIFS/NFS network shares.

Interactive wizard that generates .mount units, override configs,
credentials files, mount directories, and optionally Docker service
overrides — then installs them via sudo.
"""

import getpass
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
from rich.console import Console
from rich.table import Table


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class NasServer:
    ip: str       # e.g. "10.0.0.220"
    name: str     # e.g. "california"


@dataclass
class MountShare:
    server: NasServer
    share_name: str    # e.g. "Photos"
    mount_type: str    # "cifs" or "nfs"

    @property
    def mount_point(self) -> str:
        """E.g. /mnt/california_Photos"""
        return f"/mnt/{self.server.name}_{self.share_name}"

    @property
    def unit_name(self) -> str:
        """Systemd unit name derived from the mount point.

        systemd-escape converts ``/mnt/foo_bar`` -> ``mnt-foo_bar.mount``.
        """
        # Strip leading slash, replace remaining slashes with dashes
        escaped = self.mount_point.lstrip("/").replace("/", "-")
        return f"{escaped}.mount"

    @property
    def what(self) -> str:
        """The 'What=' value for the mount unit."""
        if self.mount_type == "cifs":
            return f"//{self.server.ip}/{self.share_name}"
        return f"{self.server.ip}:/{self.share_name}"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")


def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_server_name(name: str) -> bool:
    """Return True if *name* contains only ``[a-zA-Z0-9_]``."""
    return bool(_NAME_RE.match(name))


def validate_share_name(name: str) -> bool:
    """Return True if *name* contains only ``[a-zA-Z0-9_]``."""
    return bool(_NAME_RE.match(name))


# ---------------------------------------------------------------------------
# Ownership resolution helpers (Linux only)
# ---------------------------------------------------------------------------

def _resolve_uid(name: str) -> Optional[int]:
    """Resolve a username to a UID. Returns None on failure."""
    import pwd
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _resolve_gid(name: str) -> Optional[int]:
    """Resolve a group name to a GID. Returns None on failure."""
    import grp
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_existing_mount_units() -> List[str]:
    """Return basenames of existing ``mnt-*.mount`` units under systemd."""
    systemd_dir = Path("/etc/systemd/system")
    if not systemd_dir.is_dir():
        return []
    return sorted(
        p.name for p in systemd_dir.glob("mnt-*.mount")
    )


# ---------------------------------------------------------------------------
# Pure generation functions (no I/O)
# ---------------------------------------------------------------------------

def generate_mount_unit(share: MountShare) -> str:
    """Return the content of a ``.mount`` unit file."""
    return (
        f"[Unit]\n"
        f"Description=Mount {share.share_name} from {share.server.name} ({share.server.ip})\n"
        f"\n"
        f"[Mount]\n"
        f"What={share.what}\n"
        f"Where={share.mount_point}\n"
        f"Type={share.mount_type}\n"
        f"\n"
        f"[Install]\n"
        f"WantedBy=multi-user.target\n"
    )


def generate_override_conf(
    share: MountShare,
    credentials_path: Optional[str] = None,
    ownership: Optional[dict] = None,
) -> str:
    """Return the content of an ``override.conf`` drop-in.

    *ownership* is an optional dict with keys ``uid``, ``gid``,
    ``file_mode``, ``dir_mode`` — only applied to CIFS shares.
    """
    if share.mount_type == "cifs" and credentials_path:
        options = f"credentials={credentials_path},rw,_netdev"
    elif share.mount_type == "cifs":
        options = "rw,_netdev"
    else:
        options = "rw,_netdev,soft,timeo=150"

    # Append ownership options for CIFS mounts
    if share.mount_type == "cifs" and ownership:
        options += (
            f",uid={ownership['uid']}"
            f",gid={ownership['gid']}"
            f",file_mode={ownership['file_mode']}"
            f",dir_mode={ownership['dir_mode']}"
        )

    return (
        f"[Unit]\n"
        f"After=network-online.target remote-fs-pre.target\n"
        f"Wants=network-online.target\n"
        f"Requires=network-online.target\n"
        f"StartLimitBurst=0\n"
        f"StartLimitIntervalSec=0\n"
        f"\n"
        f"[Mount]\n"
        f"Options={options}\n"
        f"TimeoutSec=60\n"
    )


def generate_credentials_file(username: str, password: str) -> str:
    """Return the content of a Samba credentials file."""
    return f"username={username}\npassword={password}\n"


def generate_docker_override(unit_names: List[str]) -> str:
    """Return the content of a Docker service override."""
    units = " ".join(unit_names)
    return (
        f"[Unit]\n"
        f"After={units}\n"
        f"Requires={units}\n"
    )


# ---------------------------------------------------------------------------
# Installation helpers (sudo subprocess calls)
# ---------------------------------------------------------------------------

def _sudo_write(path: str, content: str, mode: Optional[str] = None) -> None:
    """Write *content* to *path* via ``sudo tee``."""
    proc = subprocess.run(
        ["sudo", "tee", path],
        input=content, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {path}: {proc.stderr.strip()}")
    if mode:
        subprocess.run(["sudo", "chmod", mode, path], check=True,
                        capture_output=True, text=True)


def _sudo_mkdir(path: str) -> None:
    """Create directory (and parents) via ``sudo mkdir -p``."""
    subprocess.run(
        ["sudo", "mkdir", "-p", path],
        check=True, capture_output=True, text=True,
    )


def _check_mount_tools(mount_type: str, console: Console) -> bool:
    """Check that mount helpers are installed. Returns True if ready."""
    tool = "mount.cifs" if mount_type == "cifs" else "mount.nfs"
    pkg = "cifs-utils" if mount_type == "cifs" else "nfs-common"

    if shutil.which(tool):
        return True
    # Also check /usr/sbin (non-root PATH may miss it)
    for sbin in ("/usr/sbin", "/sbin"):
        if os.path.isfile(os.path.join(sbin, tool)):
            return True

    console.print(f"  [yellow]\u26a0[/yellow] {tool} not found \u2014 required for {mount_type} mounts")
    console.print(f"    Install: [bold]sudo apt install {pkg} -y[/bold]")
    if click.confirm(f"  Install {pkg} now?", default=True):
        try:
            subprocess.run(
                ["sudo", "apt", "install", pkg, "-y"],
                check=True, capture_output=True, text=True,
            )
            console.print(f"  [green]\u2714[/green] Installed {pkg}")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"  [red]\u2718[/red] Failed to install: {e.stderr.strip()}")
            return False
        except FileNotFoundError:
            console.print(f"  [red]\u2718[/red] apt not found")
            return False
    return False


def _check_fstab_conflicts(shares: List[MountShare], console: Console) -> None:
    """Warn about fstab entries that conflict with the shares being installed."""
    try:
        fstab = Path("/etc/fstab").read_text()
    except OSError:
        return

    conflicts = []
    for share in shares:
        for i, line in enumerate(fstab.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            # parts[0] = device/source, parts[1] = mount point
            if parts[1] == share.mount_point or parts[0] == share.what:
                conflicts.append((i, line.strip(), share))

    if not conflicts:
        return

    console.print()
    console.print("[yellow]\u26a0  Conflicting fstab entries found:[/yellow]")
    for lineno, line, share in conflicts:
        console.print(f"    Line {lineno}: {line}")
    console.print("  Systemd mount units will fail if fstab also mounts the same path.")

    if click.confirm("  Comment out these fstab lines?", default=True):
        lines = fstab.splitlines(keepends=True)
        for lineno, _line_text, _share in conflicts:
            idx = lineno - 1
            if not lines[idx].lstrip().startswith("#"):
                lines[idx] = "# " + lines[idx]  # preserves newline
        try:
            new_content = "".join(lines)
            _sudo_write("/etc/fstab", new_content)
            console.print("  [green]\u2714[/green] Commented out conflicting fstab entries")
        except Exception as e:
            console.print(f"  [red]\u2718[/red] Could not update fstab: {e}")
            console.print("  Comment them out manually before starting the mount units.")
    else:
        console.print("  [yellow]\u26a0[/yellow] Mounts may fail \u2014 comment them out manually if needed.")


def install_shares(
    shares: List[MountShare],
    credentials: Optional[Dict[str, tuple]] = None,
    docker_override: bool = False,
    console: Optional[Console] = None,
    ownership: Optional[dict] = None,
) -> List[dict]:
    """Install all generated files via sudo and return a status list.

    *credentials* maps server name -> (username, password).
    Each entry in the returned list is ``{"share": share, "ok": bool, "error": str}``.
    """
    if console is None:
        console = Console()
    credentials = credentials or {}
    results = []

    # --- Write credentials files (once per server) ---
    written_creds: dict = {}
    for share in shares:
        sname = share.server.name
        if share.mount_type == "cifs" and sname in credentials and sname not in written_creds:
            user, pw = credentials[sname]
            cred_path = f"/etc/samba/credentials_{sname}"
            try:
                _sudo_mkdir("/etc/samba")
                _sudo_write(cred_path, generate_credentials_file(user, pw), mode="600")
                written_creds[sname] = cred_path
                console.print(f"  [green]\u2714[/green] Wrote {cred_path}")
            except Exception as e:
                console.print(f"  [red]\u2718[/red] Failed to write {cred_path}: {e}")

    # --- Install each share ---
    for share in shares:
        status: dict = {"share": share, "ok": False, "error": ""}
        unit_path = f"/etc/systemd/system/{share.unit_name}"
        override_dir = f"/etc/systemd/system/{share.unit_name}.d"
        override_path = f"{override_dir}/override.conf"
        cred_path = written_creds.get(share.server.name)

        try:
            # Mount directory
            _sudo_mkdir(share.mount_point)
            console.print(f"  [green]\u2714[/green] Created {share.mount_point}")

            # .mount unit
            _sudo_write(unit_path, generate_mount_unit(share))
            console.print(f"  [green]\u2714[/green] Wrote {unit_path}")

            # override.conf
            _sudo_mkdir(override_dir)
            own = ownership if share.mount_type == "cifs" else None
            _sudo_write(override_path, generate_override_conf(share, cred_path, own))
            console.print(f"  [green]\u2714[/green] Wrote {override_path}")

            status["ok"] = True
        except Exception as e:
            status["error"] = str(e)
            console.print(f"  [red]\u2718[/red] {share.unit_name}: {e}")

        results.append(status)

    # --- Docker override ---
    if docker_override:
        unit_names = [s.unit_name for s in shares]
        docker_dir = "/etc/systemd/system/docker.service.d"
        docker_path = f"{docker_dir}/override.conf"
        try:
            _sudo_mkdir(docker_dir)
            _sudo_write(docker_path, generate_docker_override(unit_names))
            console.print(f"  [green]\u2714[/green] Wrote {docker_path}")
        except Exception as e:
            console.print(f"  [red]\u2718[/red] Docker override: {e}")

    # --- daemon-reload ---
    try:
        subprocess.run(
            ["sudo", "systemctl", "daemon-reload"],
            check=True, capture_output=True, text=True,
        )
        console.print("  [green]\u2714[/green] systemctl daemon-reload")
    except Exception as e:
        console.print(f"  [red]\u2718[/red] daemon-reload failed: {e}")

    # --- Enable + start each unit ---
    for status in results:
        if not status["ok"]:
            continue
        share = status["share"]
        try:
            subprocess.run(
                ["sudo", "systemctl", "enable", "--now", share.unit_name],
                check=True, capture_output=True, text=True,
            )
            console.print(f"  [green]\u2714[/green] Enabled and started {share.unit_name}")
        except subprocess.CalledProcessError:
            console.print(f"  [red]\u2718[/red] Failed to start {share.unit_name}")
            try:
                proc = subprocess.run(
                    ["systemctl", "status", share.unit_name],
                    capture_output=True, text=True,
                )
                if proc.stdout:
                    console.print(f"    {proc.stdout.strip()}")
            except Exception:
                pass
            status["ok"] = False
            status["error"] = "systemctl enable --now failed"

    return results


# ---------------------------------------------------------------------------
# Preview (used by both --dry-run and the confirmation step)
# ---------------------------------------------------------------------------

def preview_shares(
    shares: List[MountShare],
    credentials: Optional[Dict[str, tuple]] = None,
    docker_override: bool = False,
    console: Optional[Console] = None,
    ownership: Optional[dict] = None,
) -> None:
    """Print a Rich table + generated file contents as a preview."""
    if console is None:
        console = Console()
    credentials = credentials or {}

    # Summary table
    table = Table(title="Mount Builder Preview")
    table.add_column("Server", style="cyan")
    table.add_column("Share")
    table.add_column("Type")
    table.add_column("Mount Point")
    table.add_column("Unit Name")

    for s in shares:
        table.add_row(
            f"{s.server.name} ({s.server.ip})",
            s.share_name,
            s.mount_type,
            s.mount_point,
            s.unit_name,
        )

    console.print(table)
    console.print()

    # File contents
    for s in shares:
        cred_path = None
        if s.mount_type == "cifs" and s.server.name in credentials:
            cred_path = f"/etc/samba/credentials_{s.server.name}"

        console.print(f"[bold]--- /etc/systemd/system/{s.unit_name} ---[/bold]")
        console.print(generate_mount_unit(s))

        override_dir = f"/etc/systemd/system/{s.unit_name}.d"
        console.print(f"[bold]--- {override_dir}/override.conf ---[/bold]")
        own = ownership if s.mount_type == "cifs" else None
        console.print(generate_override_conf(s, cred_path, own))

    # Credentials files
    for server_name, (user, _pw) in credentials.items():
        console.print(f"[bold]--- /etc/samba/credentials_{server_name} ---[/bold]")
        console.print(f"username={user}")
        console.print("password=********")
        console.print()

    # Docker override
    if docker_override:
        unit_names = [s.unit_name for s in shares]
        console.print("[bold]--- /etc/systemd/system/docker.service.d/override.conf ---[/bold]")
        console.print(generate_docker_override(unit_names))

    # Commands that will run
    console.print("[bold]Commands that will be executed:[/bold]")
    for s in shares:
        console.print(f"  sudo mkdir -p {s.mount_point}")
    console.print("  sudo systemctl daemon-reload")
    for s in shares:
        console.print(f"  sudo systemctl enable --now {s.unit_name}")
    console.print()


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------

def add_shares_to_config(
    config: dict,
    shares: List[MountShare],
    console: Optional[Console] = None,
) -> None:
    """Append mount entries to the labwatch config dict (in-memory)."""
    if console is None:
        console = Console()

    config.setdefault("checks", {})
    config["checks"].setdefault("mounts", {})
    config["checks"]["mounts"]["enabled"] = True
    existing = config["checks"]["mounts"].setdefault("mounts", [])

    existing_paths = {m.get("path") for m in existing}
    added = 0
    for share in shares:
        if share.mount_point not in existing_paths:
            existing.append({"path": share.mount_point, "severity": "critical"})
            added += 1

    if added:
        console.print(f"  [green]\u2714[/green] Added {added} mount(s) to labwatch config")
    else:
        console.print("  [dim]All mounts already in config[/dim]")


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def run_mount_builder(
    config: Optional[dict] = None,
    config_path: Optional[Path] = None,
    dry_run: bool = False,
) -> None:
    """Run the interactive mount-builder wizard."""
    console = Console()

    # --- Platform check ---
    if sys.platform != "linux":
        console.print(
            "[yellow]Mount builder is only supported on Linux.[/yellow]\n"
            "Systemd mount units require a Linux system."
        )
        return

    console.print()
    console.print("[bold cyan]Mount Builder[/bold cyan] — systemd unit generator for network shares")
    console.print()

    # --- Detect existing units ---
    existing = detect_existing_mount_units()
    if existing:
        console.print(f"[bold]Existing mount units ({len(existing)}):[/bold]")
        for name in existing:
            console.print(f"  {name}")
        console.print()

    # --- Mount type ---
    mount_type = click.prompt(
        "  Mount type",
        type=click.Choice(["cifs", "nfs"]),
        default="cifs",
    )

    # --- Check mount tools ---
    if not _check_mount_tools(mount_type, console):
        return

    # --- Collect NAS servers ---
    servers: List[NasServer] = []
    console.print()
    console.print("[bold]NAS servers[/bold]")
    while True:
        ip = click.prompt("  Server IP (empty to finish)", default="", show_default=False)
        if not ip.strip():
            if not servers:
                console.print("[yellow]  At least one server is required.[/yellow]")
                continue
            break
        ip = ip.strip()
        if not validate_ip(ip):
            console.print(f"  [red]Invalid IP address: {ip}[/red]")
            continue
        name = click.prompt("  Friendly name (e.g. california)")
        name = name.strip()
        if not validate_server_name(name):
            console.print("  [red]Name must contain only letters, numbers, and underscores.[/red]")
            continue
        servers.append(NasServer(ip=ip, name=name))
        console.print(f"  [green]\u2714[/green] Added server: {name} ({ip})")

    # --- Collect shares per server ---
    shares: List[MountShare] = []
    for server in servers:
        console.print()
        console.print(f"[bold]Shares on {server.name} ({server.ip})[/bold]")
        while True:
            share_name = click.prompt(
                "  Share name (empty to finish)",
                default="", show_default=False,
            )
            if not share_name.strip():
                break
            share_name = share_name.strip()
            if not validate_share_name(share_name):
                console.print("  [red]Share name must contain only letters, numbers, and underscores.[/red]")
                continue
            share = MountShare(server=server, share_name=share_name, mount_type=mount_type)
            shares.append(share)
            console.print(f"  [green]\u2714[/green] {share.what} -> {share.mount_point}")

    if not shares:
        console.print("[yellow]No shares configured. Exiting.[/yellow]")
        return

    # --- CIFS credentials ---
    credentials: Dict[str, tuple] = {}
    if mount_type == "cifs":
        console.print()
        console.print("[bold]CIFS credentials[/bold]")
        seen_servers = set()
        for share in shares:
            sname = share.server.name
            if sname in seen_servers:
                continue
            seen_servers.add(sname)
            console.print(f"  Credentials for {sname}:")
            user = click.prompt("    Username")
            pw = click.prompt("    Password", hide_input=True, default="", show_default=False)
            credentials[sname] = (user, pw)

    # --- CIFS ownership ---
    ownership: Optional[dict] = None
    if mount_type == "cifs":
        console.print()
        console.print("[bold]CIFS ownership[/bold]")
        console.print("  Services like Radarr/Sonarr need mount write access.")
        if click.confirm("  Set mount ownership?", default=False):
            # Group
            while True:
                group_name = click.prompt("    Group name (e.g. media)")
                gid = _resolve_gid(group_name.strip())
                if gid is not None:
                    console.print(f"    [green]\u2714[/green] Found group '{group_name.strip()}' (gid={gid})")
                    break
                console.print(f"    [red]\u2718[/red] Group '{group_name.strip()}' not found")
            # User
            while True:
                user_name = click.prompt("    User name (e.g. radarr)")
                uid = _resolve_uid(user_name.strip())
                if uid is not None:
                    console.print(f"    [green]\u2714[/green] Found user '{user_name.strip()}' (uid={uid})")
                    break
                console.print(f"    [red]\u2718[/red] User '{user_name.strip()}' not found")
            # Permissions
            perms = click.prompt("    File/dir permissions", default="0770")
            ownership = {
                "uid": uid,
                "gid": gid,
                "file_mode": perms.strip(),
                "dir_mode": perms.strip(),
            }

    # --- Docker override ---
    docker_override = False
    console.print()
    if click.confirm("  Docker containers depend on these mounts?", default=False):
        docker_override = True

    # --- Preview ---
    console.print()
    preview_shares(shares, credentials, docker_override, console, ownership)

    if dry_run:
        console.print("[dim]Dry run — no changes made.[/dim]")
        return

    # --- Confirm ---
    if not click.confirm("  Proceed with installation?", default=True):
        console.print("[dim]Cancelled.[/dim]")
        return

    # --- Check fstab conflicts ---
    _check_fstab_conflicts(shares, console)

    # --- Install ---
    console.print()
    console.print("[bold]Installing...[/bold]")
    results = install_shares(shares, credentials, docker_override, console, ownership)

    # --- Config integration ---
    if config is not None:
        console.print()
        if click.confirm("  Add these mounts to labwatch monitoring config?", default=True):
            try:
                add_shares_to_config(config, shares, console)
                if config_path:
                    from labwatch.config import save_config
                    save_config(config, config_path)
                    console.print(f"  [green]\u2714[/green] Saved config to {config_path}")
            except Exception as e:
                console.print(f"  [yellow]\u26a0[/yellow] Could not save config: {e}")

    # --- Summary ---
    console.print()
    console.print("[bold]Summary[/bold]")
    ok = sum(1 for r in results if r["ok"])
    fail = len(results) - ok
    for r in results:
        share = r["share"]
        if r["ok"]:
            console.print(f"  [green]\u2714[/green] {share.unit_name}")
        else:
            console.print(f"  [red]\u2718[/red] {share.unit_name}: {r['error']}")
    console.print(f"\n  {ok} succeeded, {fail} failed")
