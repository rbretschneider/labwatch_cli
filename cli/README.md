# labwatch

General-purpose homelab monitoring CLI. Checks system resources, Docker containers, HTTP endpoints, Nginx, DNS, systemd units, network interfaces, processes, package updates, and more — with push notifications via [ntfy](https://ntfy.sh), built-in cron scheduling, and automated Docker Compose and system package updates.

## Install

Requires Python 3.8+.

```bash
pip install git+https://github.com/rbretschneider/labwatch_cli.git#subdirectory=cli
```

Or clone and install locally:

```bash
git clone https://github.com/rbretschneider/labwatch_cli.git
cd labwatch_cli/cli
pip install .
```

For development (editable install with test deps):

```bash
pip install -e ".[test]"
```

## Quick Start

```bash
# Interactive setup — walks you through every check with descriptions,
# auto-detects Docker Compose projects, tests notifications, and sets
# up your cron schedule.
labwatch init

# Run all enabled checks once
labwatch check

# Run specific check modules
labwatch check --only system,docker

# See what Docker containers are running
labwatch discover

# Send a test notification
labwatch notify "Test" "Hello from labwatch"
```

The `labwatch init` wizard handles everything: config generation, notification testing, and cron scheduling. After running it, your checks are already running on a schedule.

## Commands

| Command | Description |
|---------|-------------|
| `labwatch init` | Interactive wizard — config, notifications, scheduling |
| `labwatch init --only docker,http` | Re-run wizard for specific sections only |
| `labwatch check` | Run all enabled checks, notify on failures |
| `labwatch check --only system,docker` | Run specific check modules |
| `labwatch check --json` | JSON output for scripting/cron |
| `labwatch discover` | List Docker containers, suggest endpoints |
| `labwatch docker-update` | Pull latest Docker images, restart changed services |
| `labwatch docker-update --dry-run` | Preview what would be updated |
| `labwatch docker-update --force` | Update even version-pinned tags |
| `labwatch system-update` | Run apt-get upgrade on Debian/DietPi systems |
| `labwatch system-update --dry-run` | Show upgradable packages without installing |
| `labwatch notify "Title" "Message"` | Send a one-off notification |
| `labwatch summarize` | Show config summary as a Rich tree |
| `labwatch validate` | Validate config file |
| `labwatch edit` | Open config in your default editor ($EDITOR) |
| `labwatch schedule check --every 5m` | Schedule checks to cron |
| `labwatch schedule check --only network --every 1m` | Schedule specific modules at their own interval |
| `labwatch schedule docker-update --every 1d` | Schedule Docker Compose updates |
| `labwatch schedule system-update --every 1w` | Schedule system package updates |
| `labwatch schedule list` | Show all labwatch cron entries |
| `labwatch schedule remove` | Remove labwatch cron entries |
| `labwatch enable docker` | Enable a check module |
| `labwatch disable docker` | Disable a check module |
| `labwatch motd` | Plain-text login summary for SSH MOTD |
| `labwatch version` | Show version |

Global options: `--config PATH`, `--no-color`, `--verbose`, `--quiet`

## What It Monitors

| Module | What it checks |
|--------|---------------|
| **system** | Disk usage per partition, RAM, CPU load with configurable thresholds |
| **docker** | Daemon health, container status (running/paused/exited/dead) |
| **http** | HTTP endpoint availability and response codes |
| **nginx** | Service status, `nginx -t` config validation, endpoint reachability |
| **systemd** | `systemctl is-active` per unit — only "active" is healthy |
| **dns** | Domain name resolution via `getaddrinfo` |
| **ping** | ICMP reachability with round-trip time |
| **network** | Per-interface: link state, IPv4 address, TX bytes (VPNs, WireGuard) |
| **process** | Verify processes running by exact name (`pgrep -x`) |
| **home_assistant** | API health, external URL, Google Home cloud, authenticated checks |
| **updates** | Pending package updates (apt/dnf/yum) with threshold alerts |
| **command** | Run shell commands, check exit codes and output patterns |

## Configuration

Config is a single YAML file at `~/.config/labwatch/config.yaml` (Linux/macOS) or `%APPDATA%\labwatch\config.yaml` (Windows). On Linux, `.config` is a hidden directory — use `ls -a ~` to see it, or open directly: `nano ~/.config/labwatch/config.yaml`.

Run `labwatch summarize` to see the resolved path and summary. Run `labwatch init` to generate it interactively. Re-run `labwatch init` to edit your config — existing values become defaults. Use `labwatch init --only http` to edit a single section. See the [main README](../README.md) for a full config example.

## Scheduling

labwatch is not a daemon — it runs once and exits. The `labwatch init` wizard sets up cron for you with a recommended schedule (grouped by check frequency), or you can customize intervals per check group. Supported intervals: `1m`–`59m`, `1h`–`23h`, `1d`, `1w`.

```bash
labwatch schedule check --only network --every 1m
labwatch schedule check --only http,dns,nginx --every 5m
labwatch schedule check --only system,docker --every 30m
labwatch schedule docker-update --every 1w
labwatch schedule system-update --every 1w
labwatch schedule list
```

## Docker Compose Auto-Updates

The wizard auto-detects Compose projects from running containers via Docker labels (`com.docker.compose.project.working_dir`). You can also scan a base directory or add paths manually.

```bash
labwatch docker-update --dry-run    # preview
labwatch docker-update              # pull and restart
labwatch docker-update --force      # include pinned tags
```

## System Package Updates

Automates `apt-get upgrade` (or `dist-upgrade`) on Debian-based systems. Configure via the wizard or manually in `update.system`:

```bash
labwatch system-update --dry-run    # preview upgradable packages
sudo labwatch system-update         # run the upgrade (requires root)
```

Modes: `safe` (apt-get upgrade, default) or `full` (apt-get dist-upgrade). Optional autoremove and auto-reboot after kernel updates.

## License

GPL v3. See [LICENSE](../LICENSE) for details.
