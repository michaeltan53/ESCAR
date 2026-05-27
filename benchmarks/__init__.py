"""Benchmarks: self-built EffectBench (paper §4.2.2 S1) plus the unified
attack suite mapping (paper §4.2.2 S2) and legacy stubs.
"""
from .effect_bench import build_effect_bench, EffectBenchSplit
from .benign_tasks import build_benign_suite
from .stub_simulators import build_agentdojo_split, build_shieldagent_split, build_badcomputeruse_split
from .unified_attack_suite import (
    UnifiedSplit, build_toolemu, build_agentdojo, build_webarena,
    build_badcomputeruse, build_unified_attack_suite, flatten,
)

__all__ = [
    "build_effect_bench", "EffectBenchSplit",
    "build_benign_suite",
    "build_agentdojo_split", "build_shieldagent_split", "build_badcomputeruse_split",
    "UnifiedSplit", "build_toolemu", "build_agentdojo", "build_webarena",
    "build_badcomputeruse", "build_unified_attack_suite", "flatten",
]
