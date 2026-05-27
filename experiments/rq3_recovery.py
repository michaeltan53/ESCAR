"""RQ3 — Declassifier-driven utility recovery (paper §4.4.2).

Reports:
  * Strict IFC, no declassifier  → benign success ≈ 68.3 %
  * With contract declassifier   → benign success ≈ 83.7 %
  * Recovery delta              ≈ +15.4 percentage points
  * UCR remains low under both regimes (≈2.4 %)
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List

from attacks.families import benign, AttackCase
from baselines.systems import PcaWFull, PcaWNoDecl
from .common import (CaseOutcome, run_baseline, unified_metrics, fmt_ci, fmt_pct)
from .stats import wilson_ci


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--n", type=int, default=200)
    args = ap.parse_args()

    print("=" * 78)
    print("RQ3: Declassifier-driven utility recovery  (paper §4.4.2)")
    print("=" * 78)

    # ESCar (no declassifier)
    no_decl = PcaWNoDecl()
    no_decl_outcomes: List[CaseOutcome] = []
    for s in range(args.seeds):
        no_decl.reset()
        no_decl_outcomes += run_baseline(no_decl, benign(s, args.n))
    m_nd = unified_metrics(no_decl_outcomes)

    # ESCar (full)
    full = PcaWFull()
    full_outcomes: List[CaseOutcome] = []
    for s in range(args.seeds):
        full.reset()
        full_outcomes += run_baseline(full, benign(s + 100, args.n))
    m_full = unified_metrics(full_outcomes)

    print(f"\n{'Configuration':<30}{'Benign success':>22}{'Overblocking':>16}{'UCR':>10}")
    print("-" * 78)
    print(f"{'ESCar (no declassifier)':<30}"
          f"{fmt_ci(m_nd['benign_succ'], *m_nd['benign_ci']):>22}"
          f"{fmt_pct(m_nd['overblocking']):>16}"
          f"{fmt_pct(m_nd['ucr']):>10}")
    print(f"{'ESCar (full / with declass.)':<30}"
          f"{fmt_ci(m_full['benign_succ'], *m_full['benign_ci']):>22}"
          f"{fmt_pct(m_full['overblocking']):>16}"
          f"{fmt_pct(m_full['ucr']):>10}")

    delta = m_full["benign_succ"] - m_nd["benign_succ"]
    print(f"\nRecovery delta: +{delta*100:.1f} percentage points  (paper claim: +15.4)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
