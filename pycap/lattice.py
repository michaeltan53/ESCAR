"""Finite security label lattice L = {⊥, H} from §3.4 of the paper.

Implements the high-water-mark IFC join: pc' = pc ⊔ ℓ(c)  and
hwm' = hwm ⊔ ℓ(resp).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, order=True)
class Label:
    rank: int
    name: str

    def __str__(self) -> str:  # for receipts / manifests
        return self.name


BOTTOM = Label(0, "BOT")
HIGH = Label(1, "H")


class Lattice:
    """Finite L = {⊥, H} with join (least upper bound)."""

    elements = (BOTTOM, HIGH)

    @staticmethod
    def join(a: Label, b: Label) -> Label:
        return a if a.rank >= b.rank else b

    @staticmethod
    def join_many(xs: Iterable[Label]) -> Label:
        out = BOTTOM
        for x in xs:
            out = Lattice.join(out, x)
        return out

    @staticmethod
    def leq(a: Label, b: Label) -> bool:
        return a.rank <= b.rank
