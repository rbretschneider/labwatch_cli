# labwatch

A CLI tool for monitoring your homelab infrastructure. Track system resources, Docker containers, systemd services, VPNs, Nginx, DNS, network interfaces, and more — all from the terminal. Schedule checks with cron, get push notifications on failures via [ntfy](https://ntfy.sh), and automate Docker Compose image updates.

## Why labwatch?

Homelabs tend to grow into a sprawl of containers, services, and network configs. Uptime dashboards are great, but they're another thing to host and maintain. **labwatch** takes a different approach: a single CLI that lives on your server, runs from cron, and pushes alerts to your phone when something breaks.

- **No web UI to host** — it's a CLI that writes to stdout and pushes to ntfy
- **Cron-native** — schedule checks and auto-updates with built-in cron management
- **Config-driven** — one YAML file defines everything to monitor
- **Extensible** — plugin architecture for checks and notification backends

## What It Monitors

| Module | What it checks |
|--------|---------------|
| **system** | Disk usage, memory, CPU load (per-partition thresholds) |
| **docker** | Daemon health, container status (running/stopped/unhealthy) |
| **http** | HTTP endpoint availability and response codes |
| **nginx** | Service status, config validation (`nginx -t`), endpoint reachability |
| **systemd** | Unit active state with configurable severity per unit |
| **dns** | Domain name resolution |
| **ping** | ICMP reachability to hosts |
| **network** | Interface link state, IP assignment, TX activity (VPN tunnels, WireGuard, etc.) |
| **process** | Verify processes are running by name |
| **home_assistant** | HA API health, external URL, Google Home/OAuth2 integration |
| **command** | Run arbitrary shell commands, validate exit codes and output patterns |

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

# Deactivate — you don't need the venv active to use labwatch
deactivate
```

Now add an alias to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) so `labwatch` works from anywhere:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias labwatch='/path/to/labwatch_cli/.venv/bin/labwatch'
```

Replace `/path/to/labwatch_cli` with the actual path where you cloned the repo. Then reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

> **Tip:** If you use cron scheduling, cron doesn't load your shell aliases. The `labwatch schedule` commands handle this automatically by resolving the full path to the binary.

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
# 1. Interactive setup — generates ~/.config/labwatch/config.yaml
labwatch init

# 2. Run all enabled checks
labwatch check

# 3. Schedule checks every 5 minutes via cron
labwatch schedule check --every 5m

# 4. Schedule Docker Compose auto-updates daily
labwatch schedule update --every 1d
```

## Commands

| Command | Description |
|---------|-------------|
| `labwatch init` | Interactive wizard to generate config |
| `labwatch check` | Run all enabled checks, notify on failures |
| `labwatch check --only system,docker` | Run specific check modules |
| `labwatch check --json` | JSON output for scripting |
| `labwatch discover` | List Docker containers, suggest HTTP endpoints |
| `labwatch update` | Pull latest Docker images and restart changed services |
| `labwatch update --dry-run` | Show what would be updated without pulling |
| `labwatch notify "Title" "Message"` | Send a one-off push notification |
| `labwatch config` | Show current config summary |
| `labwatch config --validate` | Validate config file |
| `labwatch schedule check --every 5m` | Add check schedule to cron |
| `labwatch schedule update --every 1d` | Add update schedule to cron |
| `labwatch schedule list` | Show all labwatch cron entries |
| `labwatch schedule remove` | Remove labwatch cron entries |
| `labwatch summarize` | Plain-English overview of what's configured |
| `labwatch version` | Show version |

**Global options:** `--config PATH`, `--no-color`, `--verbose`

## Configuration

Config lives at `~/.config/labwatch/config.yaml` (Linux/macOS) or `%APPDATA%\labwatch\config.yaml` (Windows).

Run `labwatch init` to generate it interactively, or create it manually:

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
    container: "nginx"        # or empty string for host-mode
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

  process:
    enabled: false
    names:
      - "redis-server"

  command:
    enabled: false
    commands:
      - name: "custom health check"
        command: "/usr/local/bin/my-check.sh"
        expect_exit: 0
        severity: "warning"

update:
  compose_dirs:
    - "/opt/stacks/media"
    - "/opt/stacks/monitoring"
```

## Scheduling with Cron

labwatch manages its own cron entries so you don't have to edit crontab by hand:

```bash
# Run checks every 5 minutes
labwatch schedule check --every 5m

# Pull and restart Docker Compose stacks daily
labwatch schedule update --every 1d

# See what's scheduled
labwatch schedule list

# Remove all labwatch cron entries
labwatch schedule remove

# Remove only check entries
labwatch schedule remove --only check
```

Supported intervals: `5m`, `15m`, `30m`, `1h`, `4h`, `12h`, `1d` (or any `Nm`, `Nh`, `Nd` pattern).

## Docker Compose Auto-Updates

labwatch can pull the latest images for your Docker Compose stacks and restart services when images change:

```bash
# Preview what would be updated
labwatch update --dry-run

# Pull and restart
labwatch update

# Force-update even version-pinned tags
labwatch update --force
```

It handles tags intelligently:
- **Rolling tags** (`latest`, `nightly`, `dev`) — always pulled
- **Pinned versions** (`1.2.3`, `v3.12-alpine`) — skipped unless `--force`
- **Digest-pinned** (`image@sha256:...`) — always skipped

## Notifications

labwatch pushes alerts via [ntfy](https://ntfy.sh) when checks fail. Severity maps to ntfy priority:

| Severity | ntfy Priority |
|----------|--------------|
| CRITICAL | Urgent |
| WARNING | High |
| OK | Low |

Configure the minimum severity threshold to control noise:

```yaml
notifications:
  min_severity: "warning"   # ignore OK results
  ntfy:
    enabled: true
    server: "https://ntfy.sh"  # or your self-hosted instance
    topic: "homelab_alerts"
```

## Docker Discovery

Not sure what to monitor? `labwatch discover` scans your running Docker containers and suggests HTTP endpoints for 23+ known services (Plex, Grafana, Home Assistant, Portainer, Jellyfin, Sonarr, Radarr, Pi-hole, and more).

```bash
labwatch discover
```

## Project Goals

- **Simple to install and run** — `pip install` and `labwatch init`, no infrastructure required
- **Cron-first scheduling** — manage monitoring schedules without external tools
- **Comprehensive homelab coverage** — system resources, Docker, systemd, VPNs, Nginx, DNS, and HTTP endpoints in one tool
- **Automated maintenance** — Docker Compose image updates on a schedule
- **Push notifications** — get alerted on your phone via ntfy when things break
- **Extensible** — add custom checks via the command module or write new check plugins
- **Scriptable** — JSON output for integration with other tools

## Contributing

Contributions are welcome. The check and notification systems use a plugin registry — adding a new check or notification backend is straightforward:

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

GPL v3 — see [LICENSE](LICENSE) for details.
