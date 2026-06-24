"""
BaseModule — abstract base class for all PenHub modules.

To create a new module:
1. Subclass BaseModule
2. Set class-level id, name, icon, group, order
3. Override router property if the module contributes API routes
4. Override get_ui_fragment() for lazy-loaded frontend component
5. Call ShellRegistry.get().register(MyModule()) at module import time
"""

from __future__ import annotations

from abc import ABC
from pathlib import Path
from typing import Optional

from fastapi import APIRouter


class BaseModule(ABC):
    """
    Declarative base for all platform modules.

    Чеклист для нового модуля — см. penhub/app.py (там пошаговая инструкция).
    Шаблон реализации — modules/hashkiller/__init__.py.
    """

    # ── Required metadata ─────────────────────────────────────────────────────
    id: str          # unique slug, e.g. "nxc-collector"
    name: str        # display name, e.g. "NXC Collector"
    icon: str = ""   # emoji or text icon for sidebar

    # ── Optional metadata ─────────────────────────────────────────────────────
    group: str  = "General"  # sidebar section label
    order: int  = 100        # sort order within group (lower = first)
    enabled: bool = True
    description: str = ""

    # ── Lazy loading ──────────────────────────────────────────────────────────
    # If True, the frontend will fetch UI fragment on first activation
    # instead of including it in the initial page load.
    lazy: bool = False

    # ── Static assets (CSS / JS pre-loaded into the shell page) ──────────────
    # Return a Path to the file inside the static/ directory, or None.
    # The shell HTML builder reads these at startup and injects <link> / <script>
    # tags automatically — no changes to collector/frontend.py needed.
    #
    # Convention: static/modules/<module-id>/module.css  and  module.js
    #
    # To add a new module with its own styles and behaviour:
    #   1. Create  static/modules/<name>/module.css  (CSS)
    #   2. Create  static/modules/<name>/module.js   (JS, defines your JS object)
    #   3. Override static_css and static_js below to point to those files.
    #   4. Register the module in penhub/app.py (already required for any module).
    #   The shell will pick up the assets automatically — no other file changes needed.

    @property
    def static_css(self) -> Optional[Path]:
        """Path to module CSS file served under /static/. None = no module CSS."""
        return None

    @property
    def static_js(self) -> Optional[Path]:
        """Path to module JS file served under /static/. None = no module JS."""
        return None

    # ── Route contribution ────────────────────────────────────────────────────

    @property
    def router(self) -> Optional[APIRouter]:
        """Return an APIRouter if this module contributes API routes, else None."""
        return None

    # ── UI fragment ───────────────────────────────────────────────────────────

    def get_ui_fragment(self) -> str:
        """
        Return the HTML fragment for this module's view.
        Used by the shell for lazy loading via GET /api/shell/module/{id}/ui.
        Returns empty string if module has no UI fragment.
        """
        return ""

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def on_startup(self) -> None:
        """
        Called once during application lifespan startup.

        IMPORTANT: Any exception raised here will prevent the entire server from
        starting. Wrap risky initialization in try/except and log errors instead
        of re-raising them, unless a failure here must be fatal for the whole app.
        """

    def on_shutdown(self) -> None:
        """Called once during application lifespan shutdown."""

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_nav_dict(self) -> dict:
        """Serializable dict for sidebar navigation."""
        return {
            "id": self.id,
            "name": self.name,
            "icon": self.icon,
            "group": self.group,
            "order": self.order,
            "enabled": self.enabled,
            "lazy": self.lazy,
        }
