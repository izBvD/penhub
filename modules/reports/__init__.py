"""
Reports Module — PenHub platform module.

Workspace-level exports in one place. Blocks:
- TIMELINE — placeholder (implementation deferred).
- EXPORTS — ALL CREDS (/api/export/allcred) and ALL VULNS (/api/export/xlsx?view=vulns).
No API or DB of its own — reuses existing export routes. Checklist: penhub/app.py.
"""

from pathlib import Path

from modules.base import BaseModule
from penhub.shell.registry import shell_registry

_STATIC = Path("static") / "modules" / "reports"


class ReportsModule(BaseModule):
    id          = "reports"
    name        = "Reports"
    icon        = "\U0001F4C4"   # 📄
    group       = "Modules"
    order       = 40
    lazy        = True
    description = "Workspace-level exports (ALL CREDS, ALL VULNS) and activity timeline."

    @property
    def static_css(self) -> Path:
        return _STATIC / "module.css"

    @property
    def static_js(self) -> Path:
        return _STATIC / "module.js"

    @property
    def router(self):
        from collector.api.timeline import router
        return router

    def get_ui_fragment(self) -> str:
        from modules.reports.ui import get_ui_fragment
        return get_ui_fragment()


shell_registry.register(ReportsModule())
