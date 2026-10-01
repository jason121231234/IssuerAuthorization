"""Fixed backend used by the paper measurements."""

from __future__ import annotations

from functools import lru_cache

from .base import GroupBackend

@lru_cache(maxsize=1)
def get_backend() -> GroupBackend:
    """Return Arkworks G1/G2 and pairing checks with py_ecc GT support."""
    from .arkworks_backend import ArkworksG1G2Backend

    return ArkworksG1G2Backend()
