"""Notification plugin registry."""

from abc import ABC, abstractmethod
from typing import Dict, List, Type

_registry: Dict[str, Type["BaseNotifier"]] = {}


def register(name: str):
    """Decorator to register a notifier class under a given name."""
    def decorator(cls):
        _registry[name] = cls
        return cls
    return decorator


def get_notifier_classes() -> Dict[str, Type["BaseNotifier"]]:
    """Return all registered notifier classes."""
    from labwatch.notifications import ntfy  # noqa: F401
    return dict(_registry)


def get_notifiers(config: dict) -> List["BaseNotifier"]:
    """Instantiate all enabled notifiers from config."""
    classes = get_notifier_classes()
    notifiers = []
    notif_cfg = config.get("notifications", {})
    for name, cls in classes.items():
        cfg = notif_cfg.get(name, {})
        if cfg.get("enabled", False):
            notifiers.append(cls(cfg))
    return notifiers


class BaseNotifier(ABC):
    """Abstract base class for notification backends."""

    def __init__(self, config: dict):
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def send(self, title: str, message: str, severity: str = "default") -> None:
        ...
