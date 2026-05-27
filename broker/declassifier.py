"""Out-of-band declassifier registry (paper §3.2 + §3.4).

Declassification policies are read-only and pinned by the platform admin
at deployment time — the LLM only has *invocation* rights, never
*definition* rights.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, Tuple


@dataclass(frozen=True)
class DeclassPolicy:
    name: str
    purpose: str
    fn: Callable[..., Any]


def _bucket(value: Any, bins: Tuple[int, ...] = (0, 300, 600), purpose: str = "") -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "unknown"
    for i, b in enumerate(sorted(bins)):
        if v < b:
            return f"bin_{i}"
    return f"bin_{len(bins)}"


def _hash(value: Any, salt: str = "esca-r-salt", purpose: str = "") -> str:
    import hashlib
    return hashlib.sha256(f"{salt}|{value}".encode()).hexdigest()[:16]


def _redact(value: Any, keep: int = 2, purpose: str = "") -> str:
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep)


class DeclassifierRegistry:
    """Frozen, append-only-at-bootstrap registry."""

    def __init__(self) -> None:
        self._policies: Dict[str, DeclassPolicy] = {}
        self._frozen = False

    def register(self, policy: DeclassPolicy) -> None:
        if self._frozen:
            raise PermissionError("declassifier registry is frozen")
        self._policies[policy.name] = policy

    def freeze(self) -> None:
        self._frozen = True

    def get(self, name: str) -> DeclassPolicy:
        if name not in self._policies:
            raise KeyError(f"unregistered declassifier: {name!r}")
        return self._policies[name]

    def has(self, name: str) -> bool:
        return name in self._policies


def default_registry() -> DeclassifierRegistry:
    reg = DeclassifierRegistry()
    reg.register(DeclassPolicy("declassify_bucket", "alert", _bucket))
    reg.register(DeclassPolicy("declassify_hash", "audit", _hash))
    reg.register(DeclassPolicy("declassify_redact", "logging", _redact))
    reg.freeze()
    return reg
