"""
Toolbox Module — PenHub platform module.

Block 2: NXCExtractor list exports (logins, passwords, hashes, IPs, spray archive).
Block 3: Operator environment config (scripts, config string copy, BloodHound config).
Block 1: Custom credential import — PLANNED (not yet implemented).
"""

from pathlib import Path

from modules.base import BaseModule
from penhub.shell.registry import shell_registry

_STATIC = Path("static") / "modules" / "toolbox"


class ToolboxModule(BaseModule):
    id          = "toolbox"
    name        = "Toolbox"
    icon        = "⚙"
    group       = "Modules"
    order       = 30
    lazy        = True
    description = (
        "NXCExtractor list exports, operator environment setup, "
        "and BloodHound config helpers."
    )

    @property
    def static_css(self) -> Path:
        return _STATIC / "module.css"

    @property
    def static_js(self) -> Path:
        return _STATIC / "module.js"

    @property
    def router(self):
        from collector.api.toolbox import router
        return router

    def get_ui_fragment(self) -> str:
        from modules.toolbox.ui import get_ui_fragment
        return get_ui_fragment()


shell_registry.register(ToolboxModule())
