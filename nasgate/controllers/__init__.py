"""Protection controllers.

A controller knows how to put one protection into the "open" (exposed) or
"closed" (protected) position, and how to report its live status. The gate
engine never talks to DSM or iptables directly; it only talks to controllers,
which keeps every protection independent and easy to add.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ControllerStatus:
    id: str
    live: str          # "open", "closed", "unknown", "error"
    detail: str = ""


class Controller(Protocol):
    id: str

    def apply(self, open_: bool) -> None:
        """Expose (open_=True) or protect (open_=False). Raises on failure."""

    def status(self) -> ControllerStatus:
        """Read the live state without changing anything."""
