"""Schema library shim.

Home Assistant replaced voluptuous with probatio, a compatible fork. Use
whichever the running release validates flows with.
"""

from __future__ import annotations

try:
    import probatio as vol
except ImportError:  # Home Assistant releases before the switch
    import voluptuous as vol  # type: ignore[no-redef]

__all__ = ["vol"]
