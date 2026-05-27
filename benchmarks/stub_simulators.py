"""Lightweight stubs for AgentDojo / ShieldAgent-Bench / BadComputerUse.

These reproducible stubs are used in the artifact-evaluation track to gauge
PcaW's generalization (RQ4) without external services. Each split mixes
attack traces and benign tasks at known proportions.
"""
from __future__ import annotations
import random
from typing import List

from attacks.families import (
    AttackCase, explicit_exfil, implicit_flow, rebinding, env_escape,
    failure_desync, benign,
)


def build_agentdojo_split(seed: int = 0, n: int = 200) -> List[AttackCase]:
    """50% benign + 30% implicit + 20% explicit."""
    rng = random.Random(seed)
    cases: List[AttackCase] = []
    cases += benign(seed + 11, n // 2)
    cases += implicit_flow(seed + 12, int(n * 0.3))
    cases += explicit_exfil(seed + 13, n - len(cases))
    rng.shuffle(cases)
    return cases


def build_shieldagent_split(seed: int = 0, n: int = 200) -> List[AttackCase]:
    """40% benign + 30% rebinding + 30% failure_desync (policy-trajectory focus)."""
    rng = random.Random(seed)
    cases: List[AttackCase] = []
    cases += benign(seed + 21, int(n * 0.4))
    cases += rebinding(seed + 22, int(n * 0.3))
    cases += failure_desync(seed + 23, n - len(cases))
    rng.shuffle(cases)
    return cases


def build_badcomputeruse_split(seed: int = 0, n: int = 200) -> List[AttackCase]:
    """20% benign + 80% env_escape (low-level escape focus)."""
    rng = random.Random(seed)
    cases: List[AttackCase] = []
    cases += benign(seed + 31, int(n * 0.2))
    cases += env_escape(seed + 32, n - len(cases))
    rng.shuffle(cases)
    return cases
