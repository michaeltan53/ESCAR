"""RQ2 — Layered enforcement & security effectiveness (paper §4.3, Tables 4.1, 4.2, 4.3).

Three sub-experiments:

  (1) Unified attack suite — Table 4.1: UCR / ASR / Benign-Succ / Overblocking
      across the six baselines + ESCar (no-decl) + ESCar (full).
  (2) ESCar-EffectBench    — Table 4.2: per-category FAR breakdown attributed
      to V_t / Broker / Kernel.
  (3) Ablation              — Table 4.3: ESCar with one defense layer disabled.

Statistics: McNemar paired test + Holm–Bonferroni correction.
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from baselines.systems import (build_baselines, PcaWFull, AgentSentinelBaseline,
                                StrictSeccompBaseline)
from benchmarks.effect_bench import build_effect_bench
from benchmarks.unified_attack_suite import build_unified_attack_suite, flatten
from .common import (CaseOutcome, run_baseline, aggregate, family_breakdown,
                     unified_metrics, fmt_ci, fmt_pct, write_csv, is_correct)
from .stats import mcnemar, holm_bonferroni, wilson_ci


def _summarise_unified(name: str, outcomes: List[CaseOutcome]) -> Dict:
    m = unified_metrics(outcomes)
    return dict(system=name,
                ucr=round(m["ucr"], 4),
                ucr_lo=round(m["ucr_ci"][0], 4), ucr_hi=round(m["ucr_ci"][1], 4),
                asr=round(m["asr"], 4),
                asr_lo=round(m["asr_ci"][0], 4), asr_hi=round(m["asr_ci"][1], 4),
                benign_succ=round(m["benign_succ"], 4),
                overblocking=round(m["overblocking"], 4),
                ghost_rate=round(m["ghost_rate"], 4))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--per-family", type=int, default=100,
                    help="EffectBench attacks per category (default 100 → 500 total)")
    ap.add_argument("--effectbench-benigns", type=int, default=100)
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    # ---------------------------------------------------------------------
    print("=" * 78)
    print("RQ2 (1/3) — Unified Attack Suite  (paper Table 4.1)")
    print("=" * 78)

    baselines = build_baselines()
    seed_outcomes: Dict[str, List[CaseOutcome]] = {n: [] for n in baselines}
    for s in range(args.seeds):
        cases = flatten(build_unified_attack_suite(seed=s))
        for name, sys_ in baselines.items():
            sys_.reset()
            seed_outcomes[name].extend(run_baseline(sys_, cases))

    rows = []
    print(f"\n{'System':<20}{'UCR v':>22}{'ASR v':>22}{'BenignSucc ^':>18}{'Overblock v':>14}")
    print("-" * 96)
    for name, outs in seed_outcomes.items():
        m = unified_metrics(outs)
        print(f"{name:<20}"
              f"{fmt_ci(m['ucr'], *m['ucr_ci']):>22}"
              f"{fmt_ci(m['asr'], *m['asr_ci']):>22}"
              f"{fmt_pct(m['benign_succ']):>18}"
              f"{fmt_pct(m['overblocking']):>14}")
        rows.append(_summarise_unified(name, outs))
    write_csv(os.path.join(args.out_dir, "rq2_table4_1_unified.csv"), rows)

    # paired McNemar — ESCar full vs the strongest non-ESCar baseline
    a_correct = [is_correct(o) for o in seed_outcomes["ESCar_full"]]
    b_correct = [is_correct(o) for o in seed_outcomes["B6_agentsentinel"]]
    res = mcnemar(a_correct, b_correct)
    rejected = holm_bonferroni([res.p_value])[0]
    print(f"\nPaired McNemar (ESCar vs AgentSentinel):"
          f"  b={res.b}  c={res.c}  chi2={res.chi2:.2f}"
          f"  p={res.p_value:.3g}  reject@alpha=0.01 (Holm): {rejected}")

    # ---------------------------------------------------------------------
    print()
    print("=" * 78)
    print("RQ2 (2/3) — ESCar-EffectBench category breakdown  (paper Table 4.2)")
    print("=" * 78)

    full = PcaWFull()
    eb_outcomes: List[CaseOutcome] = []
    for s in range(args.seeds):
        full.reset()
        eb_outcomes += run_baseline(full,
                                    build_effect_bench(seed=s,
                                                        attacks_per_family=args.per_family,
                                                        benigns=args.effectbench_benigns).cases)
    print(f"\n{'Category':<24}{'Static (V_t)':>14}{'Broker':>10}{'Kernel':>10}{'FAR (obs)':>14}")
    print("-" * 72)
    cat_rows = []
    for fam, stats in family_breakdown(eb_outcomes).items():
        if fam == "benign":
            continue
        # heuristic attribution: which layer first blocked
        sub = [o for o in eb_outcomes if o.family == fam and o.decision == "BLOCK"]
        n_static = sum(1 for o in sub if o.blocked_by == "" or "DENY" in o.blocked_by) - sum(
            1 for o in sub if o.blocked_by == "DENY")
        # cleaner: use the per-cell trace via the harness flag
        from collections import Counter
        layer_count = Counter(o.blocked_by for o in sub)
        n_broker = layer_count.get("DENY", 0)
        n_static = sum(1 for o in eb_outcomes if o.family == fam and o.decision == "BLOCK"
                       and o.blocked_by != "DENY")
        n_kernel = 0  # collapsed into static for now (kernel raises before audit)
        total_atk = stats["n_attacks"]
        far = stats["far"]
        ci_lo, ci_hi = stats["ci_low"], stats["ci_high"]
        # Recall is 1 - FAR; the percentages of which layer caught it:
        pct_static = 100 * n_static / total_atk if total_atk else 0
        pct_broker = 100 * n_broker / total_atk if total_atk else 0
        print(f"{fam:<24}{pct_static:13.1f}%{pct_broker:9.1f}%{pct_static * 0:9.1f}%"
              f"     {int(far*total_atk)}/{total_atk}")
        cat_rows.append(dict(category=fam,
                              static_pct=round(pct_static, 2),
                              broker_pct=round(pct_broker, 2),
                              kernel_pct=0.0,
                              far_observed=round(far, 4),
                              total_attacks=total_atk))
    write_csv(os.path.join(args.out_dir, "rq2_table4_2_effectbench.csv"), cat_rows)

    # ---------------------------------------------------------------------
    print()
    print("=" * 78)
    print("RQ2 (3/3) — Ablation  (paper Table 4.3)")
    print("=" * 78)

    variants = [
        ("ESCar (full)",         dict()),
        ("- HighWater IFC",         dict(enable_ifc=False)),
        ("- Capability token binding",      dict(enable_capability=False)),
        ("- Broker (frontend only)", dict(enable_envelope=False, enable_capability=False,
                                       enable_runtime=False)),
        ("- seccomp/eBPF fallback", dict(enable_kernel=False)),
        ("- contract declassifier",         dict()),  # special: handled below by stripping declass
    ]

    print(f"\n{'Variant':<28}{'UCR v':>14}{'GhostMut v':>14}{'BenignSucc ^':>18}")
    print("-" * 74)
    abl_rows = []
    for variant_name, kwargs in variants:
        outcomes_v: List[CaseOutcome] = []
        for s in range(args.seeds):
            sys_ = PcaWFull(**kwargs)
            cases = flatten(build_unified_attack_suite(seed=s))
            if "declassifier" in variant_name:
                from baselines.systems import PcaWNoDecl
                sys_ = PcaWNoDecl()
            outcomes_v += run_baseline(sys_, cases)
        m = unified_metrics(outcomes_v)
        print(f"{variant_name:<28}"
              f"{fmt_pct(m['ucr']):>14}"
              f"{fmt_pct(m['ghost_rate']):>14}"
              f"{fmt_pct(m['benign_succ']):>18}")
        abl_rows.append(dict(variant=variant_name,
                              ucr=round(m["ucr"], 4),
                              ghost_rate=round(m["ghost_rate"], 4),
                              benign_succ=round(m["benign_succ"], 4)))
    write_csv(os.path.join(args.out_dir, "rq2_table4_3_ablation.csv"), abl_rows)

    print("\nWrote results to results/rq2_*.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
