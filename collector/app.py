"""
Backward-compatible shim — canonical application is penhub.app.

All code should import from penhub.app directly:
    from penhub.app import app

This shim keeps old imports working:
    from collector.app import app  # still resolves to the full PenHub app
"""
from penhub.app import app  # noqa: F401

__all__ = ["app"]
