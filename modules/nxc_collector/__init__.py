"""
NXC Collector Module — PenHub platform module.

Provides: host/credential/auth-relation tracking, sync from nxc workspace DBs,
XLSX exports, vulnerability scanning, admin credential marking.

Phase 1: metadata registration only. Routes come from collector.api.router.
Phase 2+: routes will be contributed via self.router property.
"""

from modules.base import BaseModule
from penhub.shell.registry import shell_registry


class NxcCollectorModule(BaseModule):
    id          = "nxc-collector"
    name        = "NXC Collector"
    icon        = "📡"
    group       = "Modules"
    order       = 10
    lazy        = False        # primary module, eagerly loaded in shell
    description = (
        "Collect and analyze NXC (netexec) workspace data: "
        "hosts, credentials, auth-relations, DPAPI, shares."
    )

    def get_ui_fragment(self) -> str:
        from modules.nxc_collector.ui import get_ui_fragment
        return get_ui_fragment()


# Auto-register when module is imported
shell_registry.register(NxcCollectorModule())
