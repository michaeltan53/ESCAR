"""PcaW-EffectBench: 500 high-risk attack traces split across the five families
and 100 benign traces (paper §4.2).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List

from attacks.families import (
    AttackCase, explicit_exfil, implicit_flow, rebinding, env_escape,
    failure_desync, benign,
)


@dataclass
class EffectBenchSplit:
    cases: List[AttackCase]

    def __len__(self) -> int:
        return len(self.cases)


def build_effect_bench(seed: int = 0, attacks_per_family: int = 100,
                        benigns: int = 100) -> EffectBenchSplit:
    """Default sizes: 5 * 100 = 500 attacks (matches paper) + 100 benign."""
    cases: List[AttackCase] = []
    cases += explicit_exfil(seed + 1, attacks_per_family)
    cases += implicit_flow(seed + 2, attacks_per_family)
    cases += rebinding(seed + 3, attacks_per_family)
    cases += env_escape(seed + 4, attacks_per_family)
    cases += failure_desync(seed + 5, attacks_per_family)
    cases += benign(seed + 6, benigns)
    return EffectBenchSplit(cases=cases)
