"""File-based lock to prevent concurrent labwatch runs."""

import os
from pathlib import Path


def _lock_path() -> Path:
    """Return the lock file path, next to the config/state files."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "labwatch" / "labwatch.lock"


class Lock:
    """Exclusive file lock that prevents concurrent labwatch runs.

    Uses ``fcntl.flock`` on Unix and ``msvcrt.locking`` on Windows.
    Both auto-release when the process exits (even on crash).

    Usage::

        lock = Lock()
        if not lock.acquire():
            sys.exit(0)   # another instance is running
        try:
            ...
        finally:
            lock.release()
    """

    def __init__(self, path: Path = None):
        self._path = path or _lock_path()
        self._fd = None

    def acquire(self) -> bool:
        """Try to acquire the lock.  Returns ``False`` if already held."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Open (or create) the lock file in read-write mode
            self._fd = os.open(str(self._path), os.O_CREAT | os.O_RDWR)
        except OSError:
            return False

        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError):
            os.close(self._fd)
            self._fd = None
            return False

        # Write PID for debugging
        os.ftruncate(self._fd, 0)
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.write(self._fd, str(os.getpid()).encode())
        return True

    def release(self) -> None:
        """Release the lock.  Safe to call multiple times."""
        if self._fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
