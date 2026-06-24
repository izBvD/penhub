"""
ShellRegistry — server-side module registry for PenHub.

Modules call ShellRegistry.get().register(module) at import time.
The shell app reads the registry to:
  - include module API routers
  - generate sidebar navigation metadata for the frontend
  - serve lazy-loaded UI fragments
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from modules.base import BaseModule


class ShellRegistry:
    """Singleton module registry.  Thread-safe for reads; writes at import time only."""

    _instance: Optional["ShellRegistry"] = None

    def __init__(self) -> None:
        self._modules: dict[str, "BaseModule"] = {}

    @classmethod
    def get(cls) -> "ShellRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, module: "BaseModule") -> None:
        self._modules[module.id] = module

    def unregister(self, module_id: str) -> None:
        self._modules.pop(module_id, None)

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_module(self, module_id: str) -> "Optional[BaseModule]":
        return self._modules.get(module_id)

    def get_all(self) -> list["BaseModule"]:
        return list(self._modules.values())

    def get_enabled(self) -> list["BaseModule"]:
        return sorted(
            (m for m in self._modules.values() if m.enabled),
            key=lambda m: (m.group, m.order),
        )

    def enable(self, module_id: str) -> None:
        m = self._modules.get(module_id)
        if m:
            m.enabled = True

    def disable(self, module_id: str) -> None:
        m = self._modules.get(module_id)
        if m:
            m.enabled = False

    # ── Frontend helpers ──────────────────────────────────────────────────────

    def get_nav_config(self) -> list[dict]:
        """Serializable list of enabled modules for sidebar rendering."""
        return [m.to_nav_dict() for m in self.get_enabled()]


# Module-level singleton (created on first import)
shell_registry = ShellRegistry.get()
