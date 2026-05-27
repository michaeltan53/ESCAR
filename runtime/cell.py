"""Cell submission record."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class CellSubmission:
    source: str                      # PyCap source code
    state_in: Dict[str, Any] = field(default_factory=dict)
    label_hint: str = "BOT"
    tag: str = ""                    # debug tag
