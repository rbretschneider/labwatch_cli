"""Persistent state for notification deduplication and recovery alerts."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def _state_path() -> Path:
    """Return the path to the state file, next to the config."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "labwatch" / "state.json"


def load_state(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the state file.  Returns empty dict if missing or corrupt."""
    path = path or _state_path()
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state: Dict[str, Any], path: Optional[Path] = None) -> None:
    """Persist the state dict to disk."""
    path = path or _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)
