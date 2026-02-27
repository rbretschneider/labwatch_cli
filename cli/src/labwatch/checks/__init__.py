"""Check plugin registry."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type

from labwatch.models import CheckResult

_registry: Dict[str, Type["BaseCheck"]] = {}


def register(name: str):
    """Decorator to register a check class under a given name."""
    def decorator(cls):
        _registry[name] = cls
        return cls
    return decorator


def get_check_classes() -> Dict[str, Type["BaseCheck"]]:
    """Return all registered check classes. Import modules to trigger registration."""
    from labwatch.checks import system  # noqa: F401
    from labwatch.checks import docker  # noqa: F401
    from labwatch.checks import http  # noqa: F401
    from labwatch.checks import nginx  # noqa: F401
    from labwatch.checks import dns  # noqa: F401
    from labwatch.checks import ping  # noqa: F401
    from labwatch.checks import home_assistant  # noqa: F401
    from labwatch.checks import systemd_check  # noqa: F401
    from labwatch.checks import process_check  # noqa: F401
    from labwatch.checks import command_check  # noqa: F401
    from labwatch.checks import network_check  # noqa: F401
    from labwatch.checks import updates_check  # noqa: F401
    from labwatch.checks import smart  # noqa: F401
    from labwatch.checks import certs  # noqa: F401
    from labwatch.checks import mounts_check  # noqa: F401
    return dict(_registry)


class BaseCheck(ABC):
    """Abstract base class for all checks."""

    def __init__(self, config: dict, verbose: bool = False,
                 module_filter: str | None = None):
        self.config = config
        self.verbose = verbose
        self.module_filter = module_filter

    @abstractmethod
    def run(self) -> List[CheckResult]:
        """Execute the check and return results."""
        ...
