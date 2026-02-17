# labwatch

A CLI tool for monitoring your homelab. Tracks system resources, Docker containers, systemd services, VPNs, Nginx, DNS, network interfaces, and more. Schedules checks with cron, sends push notifications on failures via [ntfy](https://ntfy.sh), and can automate Docker Compose image updates.

## Why labwatch?

Homelabs tend to grow into a sprawl of containers, services, and network configs. Uptime dashboards are great, but they're another thing to host and maintain. labwatch takes a different approach: a single CLI that lives on your server, runs from cron, and pushes alerts to your phone when something breaks.

- No web UI to host. It writes to stdout and pushes to ntfy.
- Cron-native. Schedule checks and auto-updates with built-in cron management.
- Config-driven. One YAML file defines everything to monitor.
- Guided setup. The `labwatch init` wizard walks you through every option with detailed explanations, tests your notifications, auto-detects Docker Compose projects, and installs your cron schedule.
- Extensible. Plugin architecture for checks and notification backends.

## What It Monitors

| Module | What it checks |
|--------|---------------|
| **system** | Disk usage per partition, RAM usage, CPU load. Alerts at configurable warning/critical thresholds. |
| **docker** | Pings the Docker daemon, reports every container's status. Running = OK, paused/restarting = warning, exited/dead = critical. |
| **http** | Makes HTTP requests to your URLs. 2xx/3xx = OK, 4xx/5xx/timeout/refused = critical. |
| **nginx** | Verifies Nginx is running (systemd/pgrep or Docker), validates config with `nginx -t`, checks endpoint URLs. |
| **systemd** | Runs `systemctl is-active` per unit. Only "active" is healthy — inactive, failed, activating, etc. all trigger alerts. |
| **dns** | DNS lookups via `getaddrinfo`. Alerts if resolution fails. |
| **ping** | Single ICMP ping per host with round-trip time. Alerts if unreachable. |
| **network** | Per-interface: link state (UP/DOWN), IPv4 address assigned, TX bytes transmitted. Good for VPN tunnels and WireGuard. |
| **process** | `pgrep -x` (or tasklist on Windows) to verify processes are running by exact name. |
| **home_assistant** | HA `/api/` health, optional external URL check, optional Google Home cloud API, authenticated checks with long-lived token. |
| **updates** | Counts pending package updates (apt/dnf/yum). Warn at N+ pending, critical at M+. |
| **command** | Run any shell command. Exit 0 = OK, non-zero = failure. Optional output string matching. |

## Install

Requires **Python 3.8+**.

### Recommended: venv + shell alias

Since labwatch is a pip-installed CLI, the cleanest way to install it is inside a virtual environment with a shell alias so `labwatch` is available system-wide.

```bash
# Clone the repo
git clone https://github.com/rbretschneider/labwatch_cli.git
cd labwatch_cli

# Create a virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install ./cli

# Deactivate - you don't need the venv active to use labwatch
deactivate
```

Now add an alias to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) so `labwatch` works from anywhere:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias labwatch="$HOME/labwatch_cli/.venv/bin/labwatch"
```

Adjust the path if you cloned to a different location. Then reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

> **Note:** Cron doesn't load shell aliases. The `labwatch schedule` commands handle this by resolving the full path to the binary.

### Updating

Pull the latest code and reinstall:

```bash
cd /path/to/labwatch_cli
git pull
pip install --upgrade ./cli
# or if using a venv:
~/labwatch-venv/bin/pip install --upgrade /path/to/labwatch_cli/cli
```

### Alternative: pip install directly from GitHub

If you prefer to install into your system Python or an existing venv:

```bash
pip install git+https://github.com/rbretschneider/labwatch_cli.git#subdirectory=cli
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
#    auto-detects Docker containers and Compose projects, tests your
#    notifications, and sets up your cron schedule — all in one command.
labwatch init

# 2. Run all enabled checks (happens automatically once cron is set up)
labwatch check

# 3. Run specific check modules
labwatch check --only network,dns
```

That's it. The wizard handles config generation, notification testing, and cron scheduling. You don't need to manually edit crontab or config files unless you want to.

## The Setup Wizard

`labwatch init` is the primary way to configure labwatch. It walks through every section with explanations written for someone who may not know what each subsystem is:

1. **Hostname** — identifies your server in alerts
2. **Notifications (ntfy)** — explains what ntfy is, how to set up a server/topic, and what each field means
3. **Check modules** — each of the 12 check types gets a detailed description of exactly what it monitors, what states trigger alerts, and why you'd want it
4. **Docker auto-updates** — auto-detects Compose projects from running containers via Docker labels, or scans a base directory for compose files
5. **Summary** — shows what you enabled/disabled, your notification target, and auto-update directories
6. **Notification test** — sends a test alert to verify your ntfy setup works before you rely on it
7. **Scheduling** — explains that labwatch is not a daemon and needs cron, shows a recommended schedule grouped by frequency, and offers three options:
   - **Accept** the recommended schedule (installs cron entries immediately)
   - **Customize** per check group (choose from sensible frequency options like every 5 min, hourly, daily, weekly)
   - **None** (skip scheduling, print the manual commands for later)

You can re-run `labwatch init` at any time to reconfigure. Use `--config /tmp/test.yaml` to try it without overwriting your real config.

## Commands

| Command | Description |
|---------|-------------|
| `labwatch init` | Interactive wizard — config, notifications, scheduling |
| `labwatch check` | Run all enabled checks, notify on failures |
| `labwatch check --only system,docker` | Run specific check modules |
| `labwatch check --json` | JSON output for scripting |
| `labwatch discover` | List Docker containers, suggest HTTP endpoints |
| `labwatch update` | Pull latest Docker images and restart changed services |
| `labwatch update --dry-run` | Show what would be updated without pulling |
| `labwatch update --force` | Update even version-pinned tags |
| `labwatch notify "Title" "Message"` | Send a one-off push notification |
| `labwatch config` | Show current config summary |
| `labwatch config --validate` | Validate config file |
| `labwatch schedule check --every 5m` | Schedule all checks to cron |
| `labwatch schedule check --only network --every 1m` | Schedule specific modules at their own interval |
| `labwatch schedule update --every 1d` | Add update schedule to cron |
| `labwatch schedule list` | Show all labwatch cron entries |
| `labwatch schedule remove` | Remove all labwatch cron entries |
| `labwatch schedule remove --only check` | Remove only check entries |
| `labwatch summarize` | Plain-English overview of what's configured |
| `labwatch motd` | Plain-text login summary for SSH MOTD |
| `labwatch motd --only updates` | MOTD for specific modules only |
| `labwatch version` | Show version |

**Global options:** `--config PATH`, `--no-color`, `--verbose`

## Configuration

Config is a single YAML file. `labwatch init` creates it for you, and the wizard shows the full path at the start and end of setup. You can edit it with any text editor or re-run the wizard.

**Where is it?**

| OS | Path |
|----|------|
| Linux | `/home/yourusername/.config/labwatch/config.yaml` |
| macOS | `/Users/yourusername/.config/labwatch/config.yaml` |
| Windows | `C:\Users\yourusername\AppData\Roaming\labwatch\config.yaml` |

> **Note:** On Linux/macOS, `.config` is a hidden directory (the dot prefix hides it from `ls` by default). Use `ls -a` to see it, or just open the file directly: `nano ~/.config/labwatch/config.yaml`

Run `labwatch config` at any time to see the resolved path and a summary of what's configured. Run `labwatch init` to regenerate it interactively, or edit by hand:

```yaml
hostname: "my-server"

notifications:
  min_severity: "warning"     # only notify on warning or critical
  ntfy:
    enabled: true
    server: "https://ntfy.sh"
    topic: "homelab_alerts"

checks:
  system:
    enabled: true
    thresholds:
      disk_warning: 80
      disk_critical: 90
      memory_warning: 80
      memory_critical: 90
      cpu_load_multiplier: 2

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
    token: ""
    google_home: true

  process:
    enabled: false
    names:
      - "redis-server"

  updates:
    enabled: true
    warning_threshold: 1        # warn if any updates pending
    critical_threshold: 50      # critical if 50+ pending

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
```

## Scheduling with Cron

labwatch is not a daemon — it runs once and exits. To monitor continuously, it needs a cron job. The `labwatch init` wizard can set this up for you, or you can manage it manually with `labwatch schedule`.

labwatch manages its own cron entries so you don't have to edit crontab by hand. Use `--only` to run different check modules at different frequencies. Each `--only` combination gets its own cron entry, so they all coexist:

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
labwatch schedule update --every 1w

# See what's scheduled
labwatch schedule list

# Remove all labwatch cron entries
labwatch schedule remove

# Remove only check entries (keep update schedule)
labwatch schedule remove --only check
```

Supported intervals: `1m`–`59m`, `1h`–`23h`, `1d`, `1w`.

> **Windows:** Cron is not available. The wizard will print the equivalent commands for you to set up in Task Scheduler.

## Docker Compose Auto-Updates

labwatch can pull the latest images for your Docker Compose stacks and restart services when images change.

### Auto-detection

During `labwatch init`, labwatch reads the `com.docker.compose.project.working_dir` label from running containers to automatically find your Compose project directories. You can include all discovered projects or select individually.

If Docker isn't available, you can point labwatch at a base directory (e.g. `/home/docker`) and it will scan subdirectories for compose files (`docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`).

You can always add directories manually as well.

### Usage

```bash
# Preview what would be updated
labwatch update --dry-run

# Pull and restart
labwatch update

# Force-update even version-pinned tags
labwatch update --force
```

Tag handling:
- Rolling tags (`latest`, `nightly`, `dev`) are always pulled
- Pinned versions (`1.2.3`, `v3.12-alpine`) are skipped unless you pass `--force`
- Digest-pinned images (`image@sha256:...`) are always skipped

## Notifications

labwatch sends alerts via [ntfy](https://ntfy.sh) when checks fail. ntfy is a simple push notification service — install the ntfy app on your phone, subscribe to your topic, and you'll get alerts when something breaks.

You can use the free public server at `ntfy.sh` or self-host your own instance. The `labwatch init` wizard explains all of this and offers to send a test notification during setup.

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

## Docker Discovery

`labwatch discover` scans your running Docker containers and suggests HTTP endpoints for 23+ known services (Plex, Grafana, Home Assistant, Portainer, Jellyfin, Sonarr, Radarr, Pi-hole, and more). The `labwatch init` wizard uses this automatically when configuring HTTP checks.

```bash
labwatch discover
```

## Login MOTD

`labwatch motd` prints a plain-text status summary meant for SSH login. Drop a script into `/etc/profile.d/` and you'll see pending updates, failed services, or disk warnings every time you log in.

```bash
# /etc/profile.d/labwatch.sh
/opt/labwatch_cli/.venv/bin/labwatch motd 2>/dev/null
```

Or use `--only` to keep it focused:

```bash
# Just show pending updates and VPN status on login
/opt/labwatch_cli/.venv/bin/labwatch motd --only updates,network 2>/dev/null
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

## Project Goals

- Simple to install and run. `pip install` and `labwatch init`, nothing else required.
- Guided setup. The wizard explains everything and handles config, notification testing, and scheduling in one pass.
- Cron-first scheduling. Manage monitoring schedules without external tools.
- Cover the common homelab stack: system resources, Docker, systemd, VPNs, Nginx, DNS, HTTP endpoints.
- Granular scheduling. Different check modules can run at different intervals (VPN every minute, Docker every 30 minutes, etc.).
- Separate concerns. System updates, Docker image updates, and monitoring checks all run on independent schedules.
- Automate Docker Compose image updates with auto-detection of Compose projects.
- Push notifications via ntfy when things break.
- Extensible. Add custom checks via the command module or write new check plugins.
- Scriptable. JSON output for integration with other tools.

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
