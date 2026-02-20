```
██╗      █████╗ ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██║     ██╔══██╗██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██║     ███████║██████╔╝██║ █╗ ██║███████║   ██║   ██║     ███████║
██║     ██╔══██║██╔══██╗██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
███████╗██║  ██║██████╔╝╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

# labwatch

A CLI tool for monitoring your homelab. Tracks system resources, Docker containers, systemd services, VPNs, Nginx, DNS, network interfaces, and more. Schedules checks with cron, sends push notifications on failures via [ntfy](https://ntfy.sh), and can automate Docker Compose image updates and system package upgrades.

## Why labwatch?

Homelabs tend to grow into a sprawl of containers, services, and network configs. Uptime dashboards are great, but they're another thing to host and maintain. labwatch takes a different approach: a single CLI that lives on your server, runs from cron, and pushes alerts to your phone when something breaks.

- No web UI to host. It writes to stdout and pushes to ntfy.
- Cron-native. Schedule checks, Docker image updates, and system package upgrades with built-in cron management.
- Config-driven. One YAML file defines everything to monitor.
- Guided setup. The `labwatch init` wizard walks you through every option with detailed explanations, auto-detects Docker containers and systemd services, tests your notifications, and installs your cron schedule.
- Smart notifications. Deduplicates repeated alerts and sends recovery notices when things come back.
- Hardened for unattended use. File lock prevents overlapping runs, rotating log file provides forensic history, dead man's switch pings an external service so you know labwatch itself is still running.
- Extensible. Plugin architecture for checks and notification backends.

## What It Monitors

| Module | What it checks |
|--------|---------------|
| **system** | Disk usage per partition, RAM usage, CPU load. Alerts at configurable warning/critical thresholds. |
| **docker** | Pings the Docker daemon, reports every container's status. Running = OK, paused/restarting = warning, exited/dead = critical. |
| **http** | Makes HTTP requests to your URLs. 2xx/3xx = OK, 4xx/5xx/timeout/refused = critical. |
| **nginx** | Verifies Nginx is running (systemd/pgrep or Docker), validates config with `nginx -t`, checks endpoint URLs. |
| **systemd** | Runs `systemctl is-active` per unit. Only "active" is healthy — inactive, failed, activating, etc. all trigger alerts. Auto-discovers running services during setup. |
| **dns** | DNS lookups via `getaddrinfo`. Alerts if resolution fails. |
| **certs** | TLS certificate expiry monitoring. Connects to port 443, checks the certificate expiry date, and alerts at configurable warning/critical day thresholds. Catches silent certbot/ACME renewal failures. |
| **ping** | Single ICMP ping per host with round-trip time. Alerts if unreachable. |
| **network** | Per-interface: link state (UP/DOWN), IPv4 address assigned, TX bytes transmitted. Good for VPN tunnels and WireGuard. |
| **process** | `pgrep -x` (or tasklist on Windows) to verify processes are running by exact name. |
| **home_assistant** | HA `/api/` health, optional external URL check, optional Google Home cloud API, authenticated checks with long-lived token. |
| **updates** | Counts pending package updates (apt/dnf/yum). Warn at N+ pending, critical at M+. |
| **smart** | S.M.A.R.T. disk health for HDDs, SSDs, and NVMe via smartctl. Raspberry Pi SD/eMMC wear via sysfs. Alerts on failing health, high temps, excessive wear, reallocated sectors. |
| **command** | Run any shell command. Exit 0 = OK, non-zero = failure. Optional output string matching. |

## Install

Requires **Python 3.8+**.

### Recommended: pipx (isolated CLI install)

[pipx](https://pipx.pypa.io/) installs CLI tools in their own virtual environment so they don't pollute your system Python. It's the cleanest way to install labwatch.

```bash
# Debian 12+ / DietPi / Raspberry Pi OS (Bookworm)
sudo apt install pipx
pipx ensurepath   # adds ~/.local/bin to your PATH
source ~/.bashrc  # or open a new shell

# Install labwatch
pipx install labwatch
```

> **Older systems** (Debian 11, Ubuntu 22.04 and earlier) where `apt install pipx` isn't available:
> ```bash
> pip install pipx
> pipx ensurepath
> ```

### Alternative: pip with virtual environment

Modern Debian-based systems (Bookworm+) block `pip install` outside a venv ([PEP 668](https://peps.python.org/pep-0668/)). If you prefer pip over pipx:

```bash
python3 -m venv ~/.local/share/labwatch-venv
~/.local/share/labwatch-venv/bin/pip install labwatch

# Symlink into PATH so you can just type "labwatch"
ln -s ~/.local/share/labwatch-venv/bin/labwatch ~/.local/bin/labwatch
```

> **PATH note (DietPi / Raspberry Pi / Debian):** `~/.local/bin` may not be in your PATH by default. If `labwatch` is "command not found" after install, add this line to `~/.bashrc` and open a new shell:
> ```bash
> export PATH="$HOME/.local/bin:$PATH"
> ```
> This is not needed with pipx (which runs `ensurepath` for you).

### Updating

```bash
# Self-update from anywhere
labwatch update

# Or manually via pipx / pip
pipx upgrade labwatch
# or (if installed in a venv)
~/.local/share/labwatch-venv/bin/pip install --upgrade labwatch
```

### Development install

```bash
git clone https://github.com/rbretschneider/labwatch_cli.git
cd labwatch_cli/cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

## Quick Start

```bash
# 1. Interactive setup
#    Walks you through every check module with detailed descriptions,
#    auto-detects Docker containers and systemd services, tests your
#    notifications, and sets up your cron schedule — all in one command.
labwatch init

# 2. Run all enabled checks (happens automatically once cron is set up)
labwatch check

# 3. Run specific check modules
labwatch check --only network,dns
```

That's it. The wizard handles config generation, notification testing, and cron scheduling. You don't need to manually edit crontab or config files unless you want to.

## The Setup Wizard

`labwatch init` is the primary way to configure labwatch. It walks through every section with beginner-friendly explanations — no assumptions about what you already know:

1. **Module selection** — the fun part first. A checkbox menu of all 16 modules (14 monitoring + Docker auto-updates + system updates) with short descriptions. Pick what matches your setup; skip the rest. You can always come back.
2. **Hostname** — a friendly name for this machine (shows up in alerts so you know which server is talking)
3. **Notifications (ntfy)** — explains what ntfy is, why you want push alerts, and walks through server/topic setup
4. **Module details** — for each module you selected, configures thresholds, endpoints, devices, etc. Systemd monitoring auto-discovers running services and highlights 70+ known homelab services (Pi-hole, WireGuard, CUPS, Tailscale, Plex, etc.) so you can pick from a list instead of typing unit names from memory.
5. **Docker auto-updates** — auto-detects Compose projects from running containers via Docker labels, or scans a base directory for compose files
6. **System updates** — configures automated `apt-get upgrade` or `dist-upgrade` for Debian/DietPi, with optional autoremove and auto-reboot
7. **Summary** — shows what you enabled/disabled, your notification target, and auto-update directories
8. **Notification test** — sends a test alert to verify your ntfy setup works before you rely on it
9. **Scheduling** — explains what cron is, shows a recommended schedule grouped by frequency, and offers three options:
   - **Accept** the recommended schedule (installs cron entries immediately)
   - **Customize** per check group (choose from sensible frequency options like every 5 min, hourly, daily, weekly)
   - **None** (skip scheduling, print the manual commands for later)

Re-run `labwatch init` to edit your config — existing values become defaults. Use `labwatch init --only http` to edit a single section.

Use `--config /tmp/test.yaml` to try it without overwriting your real config.

## Commands

| Command | Description |
|---------|-------------|
| `labwatch init` | Interactive wizard — config, notifications, scheduling |
| `labwatch init --only docker,http` | Re-run wizard for specific sections only |
| `labwatch check` | Run all enabled checks, notify on failures |
| `labwatch check --only system,docker` | Run specific check modules |
| `labwatch check --json` | JSON output for scripting |
| `labwatch check --no-notify` | Run checks without sending notifications |
| `labwatch discover` | List Docker containers, suggest HTTP endpoints |
| `labwatch discover --systemd` | List systemd services, highlight known homelab services |
| `labwatch docker-update` | Pull latest Docker images and restart changed services |
| `labwatch docker-update --dry-run` | Show what would be updated without pulling |
| `labwatch docker-update --force` | Update even version-pinned tags |
| `labwatch system-update` | Run apt-get upgrade on Debian/DietPi systems |
| `labwatch system-update --dry-run` | Show upgradable packages without installing |
| `labwatch notify "Title" "Message"` | Send a one-off push notification |
| `labwatch summarize` | Show config summary as a Rich tree |
| `labwatch validate` | Validate config file |
| `labwatch edit` | Open config in your default editor |
| `labwatch modules` | List all modules with descriptions and on/off status |
| `labwatch enable docker` | Enable a check module |
| `labwatch disable docker` | Disable a check module |
| `labwatch doctor` | Check installation health and connectivity |
| `labwatch schedule check --every 5m` | Schedule all checks to cron |
| `labwatch schedule check --only network --every 1m` | Schedule specific modules at their own interval |
| `labwatch schedule docker-update --every 1d` | Add Docker update schedule to cron |
| `labwatch schedule system-update --every 1w` | Add system update schedule to cron |
| `labwatch schedule list` | Show all labwatch cron entries |
| `labwatch schedule remove` | Remove all labwatch cron entries |
| `labwatch schedule remove --only check` | Remove only check entries |
| `labwatch motd` | Plain-text login summary for SSH MOTD |
| `labwatch motd --only updates` | MOTD for specific modules only |
| `labwatch completion bash` | Print shell completion script (bash/zsh/fish) |
| `labwatch update` | Update labwatch to the latest PyPI release |
| `labwatch version` | Show version |

**Global options:** `--config PATH`, `--no-color`, `--verbose`, `--quiet`

### Exit Codes

`labwatch check` returns meaningful exit codes for scripting:

| Code | Meaning |
|------|---------|
| 0 | All checks passed (OK) |
| 1 | At least one WARNING |
| 2 | At least one CRITICAL |

## Configuration

Config is a single YAML file. `labwatch init` creates it for you, and the wizard shows the full path at the start and end of setup. You can edit it with any text editor or re-run the wizard.

**Where is it?**

| OS | Path |
|----|------|
| Linux | `/home/yourusername/.config/labwatch/config.yaml` |
| macOS | `/Users/yourusername/.config/labwatch/config.yaml` |
| Windows | `C:\Users\yourusername\AppData\Roaming\labwatch\config.yaml` |

> **Note:** On Linux/macOS, `.config` is a hidden directory (the dot prefix hides it from `ls` by default). Use `ls -a` to see it, or just open the file directly: `nano ~/.config/labwatch/config.yaml`

Run `labwatch summarize` at any time to see the resolved path and a tree view of what's configured:

```
my-server
├── Notifications enabled
│   ├── ntfy: https://ntfy.sh/homelab_alerts
│   └── min severity: warning
├── Monitoring (8 modules)
│   ├── System
│   │   ├── disk: warn 80% / crit 90%
│   │   ├── memory: warn 80% / crit 90%
│   │   └── cpu: warn 80% / crit 95%
│   ├── Docker
│   │   ├── watching: all containers
│   │   └── alert on stopped containers
│   ├── HTTP Endpoints
│   │   ├── Grafana: http://localhost:3000 (timeout 10s)
│   │   └── Plex: http://localhost:32400/identity (timeout 5s)
│   ├── DNS Resolution
│   │   ├── google.com
│   │   └── github.com
│   ├── TLS Certificates
│   │   ├── mydomain.com
│   │   └── warn at 14 days / crit at 7 days
│   ├── Ping
│   │   ├── 8.8.8.8
│   │   ├── 1.1.1.1
│   │   └── timeout: 5s
│   ├── Systemd Units
│   │   ├── docker (critical)
│   │   └── wg-quick@wg0 (critical)
│   └── Package Updates
│       ├── warn at 1+ pending
│       └── critical at 50+ pending
├── Disabled: Nginx, S.M.A.R.T., Network Interfaces, Home Assistant, Processes, Custom Commands
├── Docker auto-updates (2 directories)
│   ├── /home/docker/plex
│   └── /home/docker/grafana
└── System updates (apt-get upgrade)
    ├── mode: safe
    └── autoremove: yes
```

Run `labwatch init` to regenerate it interactively, or edit by hand:

```yaml
hostname: "my-server"

notifications:
  min_severity: "warning"     # only notify on warning or critical
  heartbeat_url: ""           # dead man's switch — see "Heartbeat" section below
  ntfy:
    enabled: true
    server: "https://ntfy.sh"
    topic: "homelab_alerts"   # or use ${NTFY_TOPIC} for env var

checks:
  system:
    enabled: true
    thresholds:
      disk_warning: 80
      disk_critical: 90
      memory_warning: 80
      memory_critical: 90
      cpu_warning: 80
      cpu_critical: 95

  docker:
    enabled: true
    watch_stopped: true
    containers: []            # empty = monitor all

  http:
    enabled: true
    endpoints:
      - name: "Grafana"
        url: "http://localhost:3000"
        timeout: 10
      - name: "Plex"
        url: "http://localhost:32400/identity"

  nginx:
    enabled: true
    container: ""             # empty = host-mode (systemd/apt)
    endpoints:
      - "https://mydomain.com"

  systemd:
    enabled: true
    units:
      - "docker"
      - name: "wg-quick@wg0"
        severity: "critical"

  network:
    enabled: true
    interfaces:
      - name: "tun0"
        severity: "critical"
      - name: "wg0"
        severity: "warning"

  dns:
    enabled: true
    domains:
      - "google.com"
      - "github.com"

  certs:
    enabled: true
    domains:
      - "mydomain.com"
      - "nextcloud.example.org"
    warn_days: 14              # warning when cert expires within 14 days
    critical_days: 7           # critical when cert expires within 7 days

  ping:
    enabled: true
    hosts:
      - "8.8.8.8"
      - "1.1.1.1"
    timeout: 5

  home_assistant:
    enabled: false
    url: "http://localhost:8123"
    external_url: ""
    token: "${HA_TOKEN}"      # env var — keeps secrets out of YAML
    google_home: true

  process:
    enabled: false
    names:
      - "redis-server"

  updates:
    enabled: true
    warning_threshold: 1        # warn if any updates pending
    critical_threshold: 50      # critical if 50+ pending

  smart:
    enabled: true
    temp_warning: 50
    temp_critical: 60
    wear_warning: 80
    wear_critical: 90
    devices: []              # empty = auto-detect all drives

  command:
    enabled: false
    commands:
      - name: "custom health check"
        command: "/usr/local/bin/my-check.sh"
        expect_exit: 0
        severity: "warning"

update:
  compose_dirs:
    - "/home/docker/plex"
    - "/home/docker/grafana"
  system:
    enabled: true
    mode: "safe"              # "safe" = apt-get upgrade, "full" = apt-get dist-upgrade
    autoremove: true
    auto_reboot: false        # set true to auto-reboot after kernel updates
```

### Environment Variables in Config

Config values can reference environment variables with `${VAR}` syntax. This keeps secrets out of the YAML file:

```yaml
home_assistant:
  token: "${HA_TOKEN}"

notifications:
  ntfy:
    topic: "${NTFY_TOPIC}"
```

Unset variables are left as-is (not expanded). Use `labwatch doctor` to check for unexpanded variables.

### Quick Enable/Disable

Toggle check modules without editing YAML or re-running the wizard:

```bash
labwatch enable dns
labwatch disable docker
```

## Scheduling with Cron

labwatch is not a daemon — it runs once and exits. To monitor continuously, it needs a cron job. The `labwatch init` wizard can set this up for you, or you can manage it manually with `labwatch schedule`.

labwatch manages its own cron entries so you don't have to edit crontab by hand. All labwatch entries are grouped inside a clearly marked block so you can tell them apart from your own cron jobs:

```
# your existing cron jobs stay untouched up here
0 * * * * /usr/bin/backup.sh

# ── LABWATCH ENTRIES (generated by labwatch init) ──
*/1 * * * * /usr/bin/labwatch check --only network # labwatch:check:network
*/5 * * * * /usr/bin/labwatch check --only dns,http,nginx,ping # labwatch:check:dns,http,nginx,ping
*/30 * * * * /usr/bin/labwatch check --only docker,system # labwatch:check:docker,system
# ── END LABWATCH ENTRIES ──
```

Use `--only` to run different check modules at different frequencies. Each `--only` combination gets its own cron entry, so they all coexist:

```bash
# Network interface checks every minute (VPN tunnels, WireGuard)
labwatch schedule check --only network --every 1m

# Service reachability every 5 minutes
labwatch schedule check --only http,dns,ping,nginx --every 5m

# System resources and Docker every 30 minutes
labwatch schedule check --only docker,system --every 30m

# Package updates daily
labwatch schedule check --only updates --every 1d

# Docker Compose image updates weekly
labwatch schedule docker-update --every 1w

# System package upgrades daily
labwatch schedule system-update --every 1w

# See what's scheduled
labwatch schedule list

# Remove all labwatch cron entries
labwatch schedule remove

# Remove only check entries (keep update schedule)
labwatch schedule remove --only check
```

Supported intervals: `1m`–`59m`, `1h`–`23h`, `1d`, `1w`.

The `--quiet` flag suppresses output when all checks pass, following the cron convention where silence means success:

```bash
# In cron: only produces output (and cron email) when something fails
labwatch -q check
```

> **Windows:** Cron is not available. The wizard will print the equivalent commands for you to set up in Task Scheduler.

## Smart Notifications

labwatch sends alerts via [ntfy](https://ntfy.sh) when checks fail. ntfy is a simple push notification service — install the ntfy app on your phone, subscribe to your topic, and you'll get alerts when something breaks.

### Deduplication and Recovery

labwatch tracks the state of each check between runs. This means:

- **No repeated alerts** — if the same check fails the same way on consecutive runs, you only get notified once
- **Escalation alerts** — if a check goes from WARNING to CRITICAL, you get a new alert
- **Recovery alerts** — when a previously failing check returns to OK, you get a `[hostname] RECOVERED` notification

State is stored in `state.json` next to the config file.

### Severity and Priority

Severity maps to ntfy priority:

| Severity | ntfy Priority |
|----------|--------------|
| CRITICAL | Urgent |
| WARNING | High |
| OK | Low |

Set the minimum severity threshold to filter out noise:

```yaml
notifications:
  min_severity: "warning"   # ignore OK results
  ntfy:
    enabled: true
    server: "https://ntfy.sh"  # or your self-hosted instance
    topic: "homelab_alerts"
```

Test your notifications at any time:

```bash
labwatch notify "Test" "Hello from labwatch"
```

## Heartbeat (Dead Man's Switch)

labwatch can ping an external monitoring service after every check run. If the pings stop arriving, the external service alerts you — catching the case where labwatch itself breaks (cron deleted, Python env corrupted, permissions changed, etc.).

This works with [Healthchecks.io](https://healthchecks.io) (free tier), [Uptime Kuma](https://github.com/louislam/uptime-kuma), or any service that accepts HTTP GET pings.

```yaml
notifications:
  heartbeat_url: "https://hc-ping.com/your-uuid-here"
```

- Pinged after every `labwatch check` run
- Appends `/fail` to the URL when checks have failures (Healthchecks.io convention)
- 10-second timeout; never crashes monitoring if the ping fails
- `labwatch doctor` verifies the URL is reachable

## Unattended Cron Hardening

When running from cron, labwatch includes three safety features that require no configuration:

**File lock** — prevents overlapping runs. If a previous `labwatch check` is still running when cron fires again, the new instance exits silently. The lock auto-releases on crash. Lock file: `~/.config/labwatch/labwatch.lock`.

**Rotating log** — every run logs to `~/.config/labwatch/labwatch.log`. Max 512KB per file with 1 backup = 1MB total on disk. Safe for Raspberry Pi SD cards.

```
2026-02-19 14:30:00 INFO check started
2026-02-19 14:30:02 INFO check complete: 8 ok, 1 failed, worst=warning
2026-02-19 14:30:02 INFO notifications sent for 1 failure(s)
2026-02-19 14:30:03 INFO heartbeat pinged
```

**Dead man's switch** — see the Heartbeat section above.

These features are active for `labwatch check`, `labwatch docker-update`, and `labwatch system-update`.

## Service Discovery

### Docker

`labwatch discover` scans your running Docker containers and suggests HTTP endpoints for 23+ known services (Plex, Grafana, Home Assistant, Portainer, Jellyfin, Sonarr, Radarr, Pi-hole, and more). The `labwatch init` wizard uses this automatically when configuring HTTP checks.

```bash
labwatch discover
```

### Systemd

`labwatch discover --systemd` lists all running systemd services and highlights 70+ recognized homelab services — Pi-hole, WireGuard, CUPS, Tailscale, Samba, Plex, Docker, Grafana, and many more. The `labwatch init` wizard uses this to present a pick-list instead of requiring you to type unit names from memory.

```bash
labwatch discover --systemd
```

## Health Check

`labwatch doctor` verifies your installation is working correctly:

```bash
labwatch doctor
```

It checks:
- Config file exists and is valid
- File permissions on the config (warns if too open)
- Unexpanded `${VAR}` references (env vars not set)
- ntfy server reachability
- Heartbeat URL reachability (if configured)
- Docker daemon accessibility
- Required system tools (`systemctl`, `pgrep`, `ping`, `ip`) for enabled checks
- Log directory is writable
- Cron entries installed
- Cron daemon is running
- labwatch binary path in each cron entry still exists on disk
- `sudo` NOPASSWD is configured for privileged cron entries (e.g. system-update)

## Shell Completion

Enable tab completion for bash, zsh, or fish:

```bash
# Bash
labwatch completion bash >> ~/.bashrc

# Zsh
labwatch completion zsh >> ~/.zshrc

# Fish
labwatch completion fish > ~/.config/fish/completions/labwatch.fish
```

## Login MOTD

`labwatch motd` prints a plain-text status summary meant for SSH login. Drop a script into `/etc/profile.d/` and you'll see pending updates, failed services, or disk warnings every time you log in.

```bash
# /etc/profile.d/labwatch.sh
labwatch motd 2>/dev/null
```

Or use `--only` to keep it focused:

```bash
# Just show pending updates and VPN status on login
labwatch motd --only updates,network 2>/dev/null
```

Example output:

```
--- labwatch | homelab ---
  [+] disk:/: 45.2% used (112.3GB free of 234.5GB)
  [!] updates: 12 pending updates
  [+] network:wg0:link: UP
  [X] network:tun0:link: DOWN
```

The output is plain text with no colors or Rich formatting, so it works in any terminal and won't break non-interactive shells.

## System Package Updates

`labwatch system-update` runs `apt-get update && apt-get upgrade -y` (or `dist-upgrade`) on Debian-based systems. It's designed to keep your servers fully patched without manual SSH sessions.

```bash
# Preview what would be upgraded
labwatch system-update --dry-run

# Run the upgrade (requires root)
sudo labwatch system-update

# Schedule weekly upgrades via cron
labwatch schedule system-update --every 1w
```

**Modes:**
- `safe` (default) — runs `apt-get upgrade`, which never removes packages or installs new dependencies
- `full` — runs `apt-get dist-upgrade`, which may remove or install packages as needed for major upgrades

**Options:**
- `autoremove` — automatically clean up unused packages after upgrade (default: on)
- `auto_reboot` — schedule `shutdown -r +1` if a kernel update requires a reboot (default: off). The 1-minute delay lets the notification send first.

**Root privileges:** System updates require root to run `apt-get`. If you're not running as root, the `labwatch init` wizard detects this and shows you exactly how to set up passwordless sudo — a single sudoers line that grants the minimum permission needed. The wizard also automatically adds `sudo` to the cron entry so scheduled updates run correctly.

Notifications are sent via ntfy on completion, with package counts, error status, and reboot status.

## Project Goals

- Simple to install and run. `pipx install labwatch` and `labwatch init`, nothing else required.
- Guided setup. The wizard explains everything and handles config, notification testing, and scheduling in one pass.
- Cron-first scheduling. Manage monitoring schedules without external tools.
- Cover the common homelab stack: system resources, Docker, systemd, VPNs, Nginx, DNS, HTTP endpoints.
- Granular scheduling. Different check modules can run at different intervals (VPN every minute, Docker every 30 minutes, etc.).
- Separate concerns. System package upgrades, Docker image updates, and monitoring checks all run on independent schedules.
- Automate Docker Compose image updates with auto-detection of Compose projects.
- Automate system package upgrades with configurable mode, autoremove, and auto-reboot.
- Smart notifications via ntfy — deduplicated, with recovery alerts.
- Extensible. Add custom checks via the command module or write new check plugins.
- Scriptable. JSON output and meaningful exit codes for integration with other tools.

## Contributing

Contributions are welcome. The check and notification systems use a plugin registry, so adding a new module is pretty simple:

1. Create a module in `src/labwatch/checks/` or `src/labwatch/notifications/`
2. Implement the base class
3. Use the `@register("name")` decorator

```bash
# Run tests
cd cli
pip install -e ".[test]"
pytest
```

## License

GPL v3. See [LICENSE](LICENSE) for details.
