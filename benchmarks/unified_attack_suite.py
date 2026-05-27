"""Unified attack suite (paper §4.2.2 / Table 4.1).

Maps each public benchmark into PyCap Cells under a shared schema:
  ⟨state_in, single PyCap source, single Manifest, zero or more effects⟩

The simulator deliberately uses synthetic Cells that exercise the *same
threat semantics* as the originals (prompt injection → tool misuse,
implicit-flow leakage, capability rebinding, low-level escape). The
benchmark name is preserved as `case.note` so per-benchmark breakdowns
are reproducible.

Composition (paper Table 4.1 sums to 144 + 629 + ~120 + 60 ≈ 953 trace-
equivalents; we keep the same 50/50 attack-vs-benign split per benchmark):
  ToolEmu        : 36 tools / 144 cases (68 attack + 76 benign)
  AgentDojo      : 97 tasks / 629 safety tests
  WebArena (sub) : ~120 cases with real external effect
  BadComputerUse : 60 escape scenarios
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import List

from attacks.families import (
    AttackCase, explicit_exfil, implicit_flow, rebinding, env_escape,
    failure_desync, benign,
)


@dataclass
class UnifiedSplit:
    name: str
    cases: List[AttackCase]


def build_toolemu(seed: int = 0, n: int = 144) -> UnifiedSplit:
    """ToolEmu — 36 tools, prompt-injection driven; mostly explicit/implicit flow."""
    rng = random.Random(seed + 101)
    n_atk = int(n * 0.47)
    cases: List[AttackCase] = []
    cases += explicit_exfil(seed + 11, n_atk // 2)
    cases += implicit_flow(seed + 12, n_atk - n_atk // 2)
    cases += benign(seed + 13, n - n_atk)
    for c in cases:
        c.note = f"toolemu/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="ToolEmu", cases=cases)


def build_agentdojo(seed: int = 0, n: int = 200) -> UnifiedSplit:
    """AgentDojo — 97 tasks, 629 safety tests; broad mix."""
    rng = random.Random(seed + 201)
    cases: List[AttackCase] = []
    cases += explicit_exfil(seed + 21, int(n * 0.18))
    cases += implicit_flow(seed + 22, int(n * 0.20))
    cases += rebinding(seed + 23, int(n * 0.10))
    cases += failure_desync(seed + 24, int(n * 0.05))
    rest = n - len(cases)
    cases += benign(seed + 25, rest)
    for c in cases:
        c.note = f"agentdojo/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="AgentDojo", cases=cases)


def build_webarena(seed: int = 0, n: int = 120) -> UnifiedSplit:
    """WebArena (subset with real external effect) — focused on outbound HTTP."""
    rng = random.Random(seed + 301)
    cases: List[AttackCase] = []
    cases += rebinding(seed + 31, int(n * 0.30))
    cases += explicit_exfil(seed + 32, int(n * 0.25))
    cases += benign(seed + 33, n - len(cases))
    for c in cases:
        c.note = f"webarena/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="WebArena-sub", cases=cases)


def build_badcomputeruse(seed: int = 0, n: int = 60) -> UnifiedSplit:
    """BadComputerUse — 60 low-level escape scenarios."""
    rng = random.Random(seed + 401)
    cases: List[AttackCase] = []
    cases += env_escape(seed + 41, int(n * 0.80))
    cases += benign(seed + 42, n - len(cases))
    for c in cases:
        c.note = f"badcomputeruse/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="BadComputerUse", cases=cases)


def build_injecagent(seed: int = 0, n: int = 110) -> UnifiedSplit:
    """InjecAgent — indirect prompt injection via tool I/O. The attacker
    embeds malicious tool-response content that triggers an unsafe tool
    call. We map this to PyCap cells where the *response* of a benign
    broker.http_get(...) is then routed into a dangerous send."""
    rng = random.Random(seed + 501)
    cases: List[AttackCase] = []
    # injection-tainted exfil
    cases += explicit_exfil(seed + 51, int(n * 0.45))
    # injection-tainted implicit flow
    cases += implicit_flow(seed + 52, int(n * 0.30))
    # benign fillers
    cases += benign(seed + 53, n - len(cases))
    for c in cases:
        c.note = f"injecagent/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="InjecAgent", cases=cases)


def build_asb(seed: int = 0, n: int = 90) -> UnifiedSplit:
    """ASB / AgentHarm-style — broad-domain harmful-action coverage.
    Heavy on destination rebinding and capability misuse."""
    rng = random.Random(seed + 601)
    cases: List[AttackCase] = []
    cases += rebinding(seed + 61, int(n * 0.35))
    cases += explicit_exfil(seed + 62, int(n * 0.30))
    cases += env_escape(seed + 63, int(n * 0.15))
    cases += benign(seed + 64, n - len(cases))
    for c in cases:
        c.note = f"asb/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="ASB", cases=cases)


def build_osharm(seed: int = 0, n: int = 70) -> UnifiedSplit:
    """OS-Harm — computer-use / OS-level harmful actions.
    Concentrated on environment escape and file/destination rebinding."""
    rng = random.Random(seed + 701)
    cases: List[AttackCase] = []
    cases += env_escape(seed + 71, int(n * 0.55))
    cases += rebinding(seed + 72, int(n * 0.20))
    cases += benign(seed + 73, n - len(cases))
    for c in cases:
        c.note = f"osharm/{c.family}"
    rng.shuffle(cases)
    return UnifiedSplit(name="OS-Harm", cases=cases)


def build_unified_attack_suite(seed: int = 0) -> List[UnifiedSplit]:
    return [
        build_toolemu(seed),
        build_agentdojo(seed),
        build_webarena(seed),
        build_badcomputeruse(seed),
    ]


def build_extended_public_suite(seed: int = 0) -> List[UnifiedSplit]:
    """Paper §5.3.2 P0 set: existing public benchmarks plus the new
    InjecAgent / ASB / OS-Harm public subsets."""
    return [
        build_toolemu(seed,        n=138),
        build_agentdojo(seed,      n=511),
        build_badcomputeruse(seed, n=53),
        build_injecagent(seed,     n=110),
        build_asb(seed,            n=90),
        build_osharm(seed,         n=70),
    ]


def flatten(splits: List[UnifiedSplit]) -> List[AttackCase]:
    return [c for s in splits for c in s.cases]
