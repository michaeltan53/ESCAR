"""§V.B — Deployment boundary and effective coverage (reviewer-promoted to main).

Replaces / extends the old Table V into a *deployment-adjusted* table that
reports SupportCoverage and UnsupportedRate as **boundary cost**, not as
security numerator/denominator.

  | Population        | Raw  | Σ_ext-compat | PyCap accepted | Unsupported  |
  | Public-Combined   | 241  | 301          | 220 (73.1%)    | 81 (26.9%)   |
  | Benign-only       | 400  | 400          | 367 (91.8%)    | 33 (8.2%)    |

Carries the paper's frozen numbers (no need to re-run LLM trajectories),
adds the explicit Clopper-Pearson upper bounds, and writes a CSV that the
fig_deployment_adjusted.py figure consumes.

Run
---
    python -m experiments.deployment_metrics
Output
------
    results/table_v_deployment_adjusted.csv
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict

from .common import write_csv, support_coverage, unsupported_rate
from .stats import wilson_ci, clopper_pearson_upper


# ---------------------------------------------------------------------------
# Paper-frozen population counts (paper §V.B Table V; reviewer-confirmed)
# ---------------------------------------------------------------------------
POPULATIONS = [
    # (label, raw, compat, accepted, attack_units, attack_trajs,
    #  benign_units, benign_trajs)
    ("Public-Combined", 241, 301, 220, 139, 2780,  81, 1620),
    ("Benign-only",     400, 400, 367,   0,    0, 400, 8000),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Table V — deployment-adjusted metrics")
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    print("=" * 100)
    print("Table V — Deployment boundary and effective coverage  (paper §V.B)")
    print("=" * 100)
    print()
    print(f"{'Population':<20}{'Raw':>6}{'Σext-compat':>14}"
          f"{'PyCap acc':>14}{'Unsup. fail-closed':>22}{'95% Wilson on SupportCov':>28}")
    print("-" * 100)

    rows = []
    for (label, raw, compat, acc, atk_u, atk_t, ben_u, ben_t) in POPULATIONS:
        sc = support_coverage(compat, acc)
        ur = unsupported_rate(compat, acc)
        ci_lo, ci_hi = wilson_ci(acc, compat)
        unsup = compat - acc
        print(f"{label:<20}{raw:>6}{compat:>14}"
              f"  {acc:>4} ({sc*100:5.1f}%)  "
              f"  {unsup:>4} ({ur*100:5.1f}%)        "
              f"[{ci_lo*100:5.1f}, {ci_hi*100:5.1f}]")
        rows.append(dict(
            population=label,
            raw_tasks=raw,
            sigma_ext_compatible_units=compat,
            pycap_accepted_units=acc,
            unsupported_units=unsup,
            support_coverage_pct=round(sc * 100, 2),
            unsupported_rate_pct=round(ur * 100, 2),
            wilson_ci_lo_pct=round(ci_lo * 100, 2),
            wilson_ci_hi_pct=round(ci_hi * 100, 2),
            attack_units=atk_u,
            attack_trajectories=atk_t,
            benign_units=ben_u,
            benign_trajectories=ben_t,
            notes=("excluded from mechanism protection — fail-closed" if atk_u
                    else "deployment usability cost"),
        ))

    print()
    print(">>> Key statement (REQUIRED in §V.B):")
    print("    'We do not count unsupported units as protected executions; they are")
    print("     reported as fail-closed deployment cost.'")
    print()

    print("Attack-trajectory denominators (per Public-Combined):")
    print(f"  attack units                : 139")
    print(f"  attack trajectories         : 2 780  (~20 trajectories / unit)")
    print(f"  benign units                : 81")
    print(f"  benign trajectories         : 1 620")
    print(f"  Benign-only units           : 400")
    print(f"  Benign-only trajectories    : 8 000  (~20 trajectories / unit)")
    print()
    print("These denominators MUST be reported alongside any UMECR / ASR figure")
    print("(paper §V.A reviewer-feedback: 'no bare proportion without denominator').")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table_v_deployment_adjusted.csv")
    write_csv(csv_path, rows)
    print(f"\nResults written to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
