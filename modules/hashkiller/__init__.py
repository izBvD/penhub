"""
HashKiller Module — PenHub platform module.
Используй этот файл как шаблон при создании нового модуля.
Чеклист: penhub/app.py.

Provides: global NT hash → plaintext database, bulk import from .potfile files,
kill_workspace (fill brutforced column), SMART enrichment, export hashes for hashcat.
"""

from pathlib import Path

from modules.base import BaseModule
from penhub.shell.registry import shell_registry

_STATIC = Path("static") / "modules" / "hashkiller"


class HashKillerModule(BaseModule):
    id          = "hashkiller"
    name        = "HashKiller"
    icon        = "🗡"
    group       = "Modules"
    order       = 20
    lazy        = True         # loaded on first user activation (saves initial page weight)
    description = (
        "Global NT hash:plaintext database. "
        "Import .potfile files, crack hashes, SMART-enrich from workspace credentials."
    )

    @property
    def static_css(self) -> Path:
        return _STATIC / "module.css"

    @property
    def static_js(self) -> Path:
        return _STATIC / "module.js"

    def get_ui_fragment(self) -> str:
        from modules.hashkiller.ui import get_ui_fragment
        return get_ui_fragment()


# Auto-register when module is imported
shell_registry.register(HashKillerModule())
