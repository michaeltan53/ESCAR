"""§5.3.1 — Native-CodeBench locked test-set main result (RQ3).

Three apertures (paper §5.3.1):

  * deployment   (n = 288) — full test set, rejected attack counts as
                              attack failure, rejected benign counts as
                              benign failure (utility cost).
  * accepted     (n ≤ 288) — only PyCap-accepted tasks, isolates the
                              Broker authorization closed-loop.
  * rejected     (residual) — fail-closed boundary cost (benign utility loss).

All baselines (paper §5.1.2): No-Defense, Sandbox-only,
Policy-only/no-static-manifest, Static-manifest-only/no-Broker,
ShieldAgent, Progent-equivalent, ESCar (full).

Run
---
    python -m experiments.native_codebench_main [--seeds N]
Output
------
    results/table5_3_native_codebench.csv
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from baselines.systems import build_baselines_v3
from benchmarks.native_codebench import (
    build_native_codebench, test_split, NativeTask,
)
from .common import (
    run_baseline, CaseOutcome, write_csv,
    task_ucr_deploy, task_ucr_accepted,
    asr_deploy, asr_accepted, benign_success_deploy,
    umec_rate, accept_rate,
    # Paper §V.A reviewer-feedback metrics
    accepted_umec_rate, unit_umec_rate, task_layer_residual_risk,
    deployment_benign_completion, unit_clustered_outcomes,
)
from .stats import (bootstrap_ci, clustered_bootstrap_ci,
                     clopper_pearson_upper, mcnemar, holm_bonferroni)


def _to_cases(tasks: List[NativeTask]):
    """Adapt NativeTask -> AttackCase for run_baseline. The task index is
    stamped into case.note prefixed with 'unit_id=' so the harness can later
    populate CaseOutcome.unit_id for clustered bootstrap."""
    out = []
    for i, t in enumerate(tasks):
        # tag the unit id so run_baseline can pick it up
        t.case.note = f"unit_id=NCB-{t.effect_class}-{i:04d} | {t.case.note}"
        out.append(t.case)
    return out


def _stamp_unit_ids(outcomes):
    """Populate CaseOutcome.unit_id from the note prefix written by _to_cases."""
    for o in outcomes:
        for tag in (o.family or "").split("|") + ((o.blocked_by or "")).split("|"):
            pass
    # We tagged via family.note; outcomes don't carry the source note directly,
    # so we use a stable hash of (family + decision pattern) as a unit proxy.
    # For real clustering, run_baseline now passes the unit_id through.
    return outcomes


def main() -> int:
    ap = argparse.ArgumentParser(description="Table 5.3 — Native-CodeBench main result")
    ap.add_argument("--seeds", type=int, default=3,
                    help="Random seeds (paper uses 5; default 3 for speed)")
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    print("=" * 100)
    print("SHARED-SUBSET MECHANISM COMPARISON  (paper §V.E, renamed per reviewer)")
    print("=" * 100)
    print()
    print("This comparison isolates mechanism behavior on mutually executable")
    print("trajectories. It does NOT include PyCap-unsupported units, which are")
    print("accounted for separately in Table V (run: python -m experiments.deployment_metrics).")

    baselines = build_baselines_v3()
    paper_seeds = [17, 29, 43, 59, 71][:args.seeds]

    # Accumulate outcomes per system across seeds
    by_sys: Dict[str, List[CaseOutcome]] = {n: [] for n in baselines}
    for s in paper_seeds:
        tasks = test_split(build_native_codebench(seed=s))
        cases = _to_cases(tasks)
        for name, sys_inst in baselines.items():
            sys_inst.reset()
            by_sys[name].extend(run_baseline(sys_inst, cases))

    rows = []
    print(f"\n{'System':<32}{'n':>5}{'Task-UCR^dep':>15}{'ASR^dep':>12}"
          f"{'Benign':>10}{'UMECR':>10}{'AcceptRate':>14}")
    print("-" * 100)
    for name, outs in by_sys.items():
        n = len(outs)
        ucr_d = task_ucr_deploy(outs)
        ucr_a = task_ucr_accepted(outs)
        asr_d = asr_deploy(outs)
        asr_a = asr_accepted(outs)
        bs = benign_success_deploy(outs)
        umec = umec_rate(outs)
        ar = accept_rate(outs)

        # Single-sided Clopper-Pearson UB for UMECR (zero-event aware)
        atks = sum(1 for o in outs if o.truth == "ATTACK")
        umec_n = sum(1 for o in outs if o.unauthorized_modeled_commit)
        umec_ub = clopper_pearson_upper(umec_n, max(atks, 1))

        # Paper §V.A reviewer-mandated metrics
        a_umec = accepted_umec_rate(outs)
        u_umec = unit_umec_rate(outs)
        depl_bs = deployment_benign_completion(outs)
        residual = task_layer_residual_risk(outs)

        # Cluster-bootstrap CI on unit-level UMECR (the PRIMARY uncertainty)
        # — reviewers required clustered CI because trajectories are NOT
        # independent Bernoulli trials.
        attack_outs = [o for o in outs if o.truth == "ATTACK" and not o.pycap_rejected]
        cb_lo = cb_hi = 0.0
        if attack_outs:
            values = [1.0 if o.unauthorized_modeled_commit else 0.0 for o in attack_outs]
            cluster_ids = [o.unit_id for o in attack_outs]
            _, cb_lo, cb_hi = clustered_bootstrap_ci(values, cluster_ids,
                                                       reps=2000,
                                                       statistic="any")

        print(f"{name:<32}{n:>5}"
              f"{ucr_d*100:>12.1f}% "
              f"{asr_d*100:>10.1f}% "
              f"{bs*100:>8.1f}% "
              f"{u_umec*100:>8.2f}% "
              f"{ar*100:>12.1f}%")
        rows.append(dict(
            system=name, n=n,
            task_ucr_deploy_pct=round(ucr_d * 100, 2),
            task_ucr_accepted_pct=round(ucr_a * 100, 2),
            asr_deploy_pct=round(asr_d * 100, 2),
            asr_accepted_pct=round(asr_a * 100, 2),
            benign_success_pct=round(bs * 100, 2),
            # Trajectory-level (kept for comparability)
            umecr_traj_pct=round(umec * 100, 4),
            umecr_traj_upper_ci_pct=round(umec_ub * 100, 4),
            # NEW: paper §V.A reviewer-mandated
            accepted_umec_pct=round(a_umec * 100, 4),
            unit_umec_pct=round(u_umec * 100, 4),
            unit_umec_cluster_ci_lo_pct=round(cb_lo * 100, 4),
            unit_umec_cluster_ci_hi_pct=round(cb_hi * 100, 4),
            deployment_benign_completion_pct=round(depl_bs * 100, 2),
            task_layer_residual_risk_pct=round(residual * 100, 4),
            accept_rate_pct=round(ar * 100, 2),
        ))

    # ---- Pairwise McNemar tests: ESCar vs every other baseline ---
    print("\n--- Paired McNemar (ESCar_full vs others) — Holm-Bonferroni corrected ---")
    escar_correct = [(o.policy_violating_commits == 0)
                      for o in by_sys["ESCar_full"]]
    p_vals = []
    names = []
    for name, outs in by_sys.items():
        if name == "ESCar_full":
            continue
        baseline_correct = [(o.policy_violating_commits == 0) for o in outs]
        res = mcnemar(escar_correct, baseline_correct)
        p_vals.append(res.p_value)
        names.append(name)
        print(f"  ESCar vs {name:<32} b={res.b:<4} c={res.c:<4} "
              f"chi2={res.chi2:6.2f} p={res.p_value:.3g}")
    rej = holm_bonferroni(p_vals, alpha=0.01)
    print("\n  Holm-Bonferroni @ alpha=0.01:")
    for n, r in zip(names, rej):
        print(f"    {n:<32}  reject H0: {r}")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table5_3_native_codebench.csv")
    write_csv(csv_path, rows)
    print(f"\nResults written to {csv_path}")
    print("\nLegend (paper §V.A Metric Glossary):")
    print("  Task-UCR^dep : per-task unsafe-commit rate over the full test set")
    print("  ASR^dep      : attack-success rate over all attack tasks (any commit OR ALLOW)")
    print("  Benign       : benign-task success in deployment aperture")
    print("  UMECR (col)  : Unit-UMECR  = units with >=1 unauth modeled commit /")
    print("                                accepted attack units                  (cluster-CI in CSV)")
    print("  AcceptRate   : fraction of tasks PyCap admitted (= 1 - reject rate)")
    print()
    print("CSV columns include: accepted_umec_pct, unit_umec_pct,")
    print("  unit_umec_cluster_ci_{lo,hi}_pct, deployment_benign_completion_pct,")
    print("  task_layer_residual_risk_pct, umecr_traj_pct (legacy trajectory-level).")
    print()
    print("REMINDER: PyCap-unsupported units are NOT counted as protected here;")
    print("see Table V (deployment_metrics.py) for the boundary-cost row.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
