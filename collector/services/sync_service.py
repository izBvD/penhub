"""
Credential normalization for the sync pipeline.
"""

from collector.core.constants import _LM_EMPTY, _NT_EMPTY

EMPTY_PASSWORD = "<empty_password>"

# SYNC NOTE: normalize_password logic is duplicated in nxc_updater.py (standalone tool).
# If you change the normalization rules here, update nxc_updater.py accordingly.
def normalize_password(password: str, credtype: str) -> tuple:
    """
    Normalize passwords to a canonical form:
    - Strip LM prefix from LM:NT hash pairs
    - Empty NT hash (31d6...) → EMPTY_PASSWORD, plaintext
    - Empty plaintext password ("") → EMPTY_PASSWORD, plaintext
    Returns (normalized_password, possibly_changed_credtype).
    """
    p = password
    if p and p[:len(_LM_EMPTY)].lower() == _LM_EMPTY:
        p = p[len(_LM_EMPTY):]
    if credtype == "hash" and p.lower() == _NT_EMPTY:
        return EMPTY_PASSWORD, "plaintext"
    if credtype == "plaintext" and p == "":
        return EMPTY_PASSWORD, "plaintext"
    return p, credtype
