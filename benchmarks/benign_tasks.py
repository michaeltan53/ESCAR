"""Benign benchmark suite (`Bench-USR` analogue) for utility/recovery tests."""
from __future__ import annotations
from typing import List

from attacks.families import AttackCase, benign


def build_benign_suite(seed: int = 0, n: int = 200) -> List[AttackCase]:
    return benign(seed, n)
