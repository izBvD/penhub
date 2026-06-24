"""
NXC Collector UI — shell integration.

NXC Collector is the primary (eagerly-loaded) module.
Its full HTML/JS is assembled by collector/frontend.py from collector/_frontend/ parts,
so get_ui_fragment() returns an empty string — no lazy fetch needed.
"""


def get_ui_fragment() -> str:
    return ""
