# labwatch

General-purpose homelab monitoring CLI. Checks system resources, Docker containers, and HTTP endpoints, with push notifications via [ntfy](https://ntfy.sh).

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

For development (editable install):

```bash
pip install -e .
```

## Quick Start

```bash
# Interactive setup — generates ~/.config/labwatch/config.yaml
labwatch init

# Run all enabled checks
labwatch check

# Run only system checks (disk, memory, CPU)
labwatch check --only system

# See what Docker containers are running
labwatch discover

# Send a test notification
labwatch notify "Test" "Hello from labwatch"
```

## Commands

| Command | Description |
|---------|-------------|
| `labwatch init` | Interactive wizard to generate config |
| `labwatch check` | Run all enabled checks, notify on failures |
| `labwatch check --only system,docker` | Run specific check modules |
| `labwatch check --json` | JSON output for scripting/cron |
| `labwatch discover` | List Docker containers, suggest endpoints |
| `labwatch notify "Title" "Message"` | Send a one-off notification |
| `labwatch config` | Show current config summary |
| `labwatch config --validate` | Validate config file |
| `labwatch version` | Show version |

Global options: `--config PATH`, `--no-color`, `--verbose`

## Configuration

Config lives at `~/.config/labwatch/config.yaml` (Linux/macOS) or `%APPDATA%\labwatch\config.yaml` (Windows). Run `labwatch init` to generate it, or create manually:

```yaml
hostname: "my-server"

notifications:
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
    containers: []          # empty = monitor all containers

  http:
    enabled: true
    endpoints:
      - name: "Home Assistant"
        url: "http://localhost:8123/api/"
        timeout: 10
      - name: "Plex"
        url: "http://localhost:32400/identity"
        timeout: 10
```

## Running on a Schedule

Add to crontab for periodic monitoring:

```bash
# Every 5 minutes
*/5 * * * * labwatch check 2>&1 | logger -t labwatch
```

Or with systemd timer, or any scheduler you prefer.
