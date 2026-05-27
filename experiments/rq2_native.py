"""RQ2 — Per-benchmark native-semantics security results (paper §4.3 / Table 4.3).

Reports Task-UCR and ASR per (benchmark × baseline), in the benchmark's
native task definition (i.e. each cell counts once for Task-UCR, irrespective
of how many MUT effects it contains).

  * Task-UCR_j = (1/|T_j|) Σ_t  1[ ∃ e ∈ Mut_t : Unsafe(e) ]
  * ASR_j     = (1/|A_j|) Σ_a  1[ GoalReached(a) ]

Baselines (paper-aligned):
  B0 — no defense          (NativeBaseline)
  B1 — strict seccomp      (StrictSeccompBaseline)
  B2 — gVisor              (GVisorBaseline)
  B3 — IsolateGPT          (IsolateGPTBaseline)
  B5 — ShieldAgent         (ShieldAgentBaseline)
  ESCar (full)

Benchmarks (paper-aligned counts):
  ToolEmu        : 138 retained
  AgentDojo      : 511 retained
  BadComputerUse :  53 retained

Run
---
    python -m experiments.rq2_native [--seeds N]

Output
------
    results/table4_3_native_security.csv
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from baselines.systems import (
    NativeBaseline, StrictSeccompBaseline, GVisorBaseline,
    IsolateGPTBaseline, ShieldAgentBaseline, PcaWFull,
)
from benchmarks.unified_attack_suite import (
    build_toolemu, build_agentdojo, build_badcomputeruse,
)
from .common import run_baseline, CaseOutcome, write_csv
from .stats import wilson_ci, bootstrap_ci, mcnemar, holm_bonferroni


PAPER_KEPT = {
    "ToolEmu":        138,
    "AgentDojo":      511,
    "BadComputerUse":  53,
}


def _task_ucr_asr(outcomes: List[CaseOutcome]) -> Dict[str, float]:
    """Compute Task-UCR and ASR per paper §4.1 definitions.

    Task-UCR = per-cell indicator: any policy-violating MUT was committed.
    ASR      = per-attack indicator: goal reached (we proxy goal-reached as
               'any policy-violating commit on an attack-labelled cell').
    """
    # per-cell indicators
    task_ucr_indicators = [1.0 if o.policy_violating_commits > 0 else 0.0
                            for o in outcomes]
    attacks = [o for o in outcomes if o.truth == "ATTACK"]
    asr_indicators = [1.0 if (o.policy_violating_commits > 0 or o.decision == "ALLOW") else 0.0
                       for o in attacks]
    task_ucr = sum(task_ucr_indicators) / max(len(task_ucr_indicators), 1)
    asr = sum(asr_indicators) / max(len(asr_indicators), 1)
    return dict(task_ucr=task_ucr, asr=asr,
                ucr_values=task_ucr_indicators,
                asr_values=asr_indicators)


SYSTEM_LABELS = [
    ("B0_no_defense",     NativeBaseline,        "B0 No defense"),
    ("B1_strict_seccomp", StrictSeccompBaseline, "B1 Strict seccomp"),
    ("B2_gvisor",         GVisorBaseline,        "B2 gVisor"),
    ("B3_isolategpt",     IsolateGPTBaseline,    "B3 IsolateGPT"),
    ("B5_shieldagent",    ShieldAgentBaseline,   "B5 ShieldAgent"),
    ("ESCar_full",        PcaWFull,              "ESCar (full)"),
]

BENCHMARKS = [
    ("ToolEmu",        build_toolemu,        PAPER_KEPT["ToolEmu"]),
    ("AgentDojo",      build_agentdojo,      PAPER_KEPT["AgentDojo"]),
    ("BadComputerUse", build_badcomputeruse, PAPER_KEPT["BadComputerUse"]),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Table 4.3 — Per-benchmark native semantics")
    ap.add_argument("--seeds", type=int, default=5,
                    help="Number of random seeds (paper uses 5: {17,29,43,59,71})")
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    paper_seeds = [17, 29, 43, 59, 71][:args.seeds]

    print("=" * 96)
    print("RQ2 — Per-benchmark native-semantics security  (paper §4.3 / Table 4.3)")
    print("=" * 96)

    rows = []
    print(f"\n{'Benchmark':<18}{'Method':<22}{'Task-UCR (%)':>22}{'ASR (%)':>22}")
    print("-" * 96)

    # Per-(benchmark, system) accumulated outcomes
    outcomes_by_bench_sys: Dict[str, Dict[str, List[CaseOutcome]]] = {}

    for bench_name, builder, n_kept in BENCHMARKS:
        outcomes_by_bench_sys[bench_name] = {}
        for sys_id, _SysCls, _label in SYSTEM_LABELS:
            outcomes_by_bench_sys[bench_name][sys_id] = []

        for seed in paper_seeds:
            split = builder(seed=seed, n=n_kept)
            for sys_id, SysCls, _label in SYSTEM_LABELS:
                sys_inst = SysCls()
                sys_inst.reset()
                outcomes_by_bench_sys[bench_name][sys_id].extend(
                    run_baseline(sys_inst, split.cases)
                )

        # Print per-benchmark block
        for sys_id, _SysCls, label in SYSTEM_LABELS:
            outs = outcomes_by_bench_sys[bench_name][sys_id]
            m = _task_ucr_asr(outs)
            ucr_lo, ucr_hi = bootstrap_ci(m["ucr_values"], reps=2000, seed=hash(sys_id) & 0xffff)
            asr_lo, asr_hi = bootstrap_ci(m["asr_values"], reps=2000, seed=(hash(sys_id) + 1) & 0xffff)
            print(f"{bench_name:<18}{label:<22}"
                  f"  {m['task_ucr']*100:5.1f} [{ucr_lo*100:4.1f}, {ucr_hi*100:4.1f}]  "
                  f"  {m['asr']*100:5.1f} [{asr_lo*100:4.1f}, {asr_hi*100:4.1f}]")
            rows.append(dict(
                benchmark=bench_name, system=label, n=len(outs),
                task_ucr=round(m["task_ucr"] * 100, 2),
                task_ucr_lo=round(ucr_lo * 100, 2),
                task_ucr_hi=round(ucr_hi * 100, 2),
                asr=round(m["asr"] * 100, 2),
                asr_lo=round(asr_lo * 100, 2),
                asr_hi=round(asr_hi * 100, 2),
            ))
        print("-" * 96)

    # ---- McNemar paired test: ESCar vs strongest non-ESCar baseline (B5) ----
    print("\nPaired McNemar (ESCar vs B5 ShieldAgent), per benchmark — Holm-Bonferroni corrected:")
    p_values = []
    for bench_name, _, _ in BENCHMARKS:
        a = [(o.policy_violating_commits == 0) for o in outcomes_by_bench_sys[bench_name]["ESCar_full"]]
        b = [(o.policy_violating_commits == 0) for o in outcomes_by_bench_sys[bench_name]["B5_shieldagent"]]
        res = mcnemar(a, b)
        p_values.append(res.p_value)
        print(f"  {bench_name:<18} b={res.b:<5} c={res.c:<5} chi2={res.chi2:6.2f} p={res.p_value:.3g}")
    rejected = holm_bonferroni(p_values, alpha=0.01)
    for (bench_name, _, _), rej in zip(BENCHMARKS, rejected):
        print(f"  {bench_name:<18} reject H0 @ alpha=0.01 (Holm): {rej}")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table4_3_native_security.csv")
    write_csv(csv_path, rows)
    print(f"\nResults written to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
