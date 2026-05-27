"""RQ1 — Manifest extraction (paper §4.4.1, Table 4.4a).

Asks: can the verifier produce a tight, sound effect manifest on benign
public-benchmark cells?

Reports:
  * PyCap initial syntax-acceptance rate on AgentDojo benign subset (paper: 94.0% [92.1, 95.5])
  * Failure-root-cause breakdown (Table 4.4a)
  * Manifest tightness: distribution of |Ê_t| (declared effects) and label
    ceilings; demonstrates the verifier is conservative-but-tight.
"""
from __future__ import annotations
import argparse
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from attacks.families import benign
from baselines.systems import PcaWFull
from benchmarks.unified_attack_suite import build_agentdojo
from pycap.grammar import syntax_filter, PyCapSyntaxError
from runtime.cell import CellSubmission
from runtime.cvm import CVM
from .common import wilson_ci, fmt_ci


def _classify_failure(err: str) -> str:
    if any(k in err for k in ("eval", "exec", "import")):
        return "exec/eval/dynamic-import"
    if "while" in err:
        return "unbounded while/recursion"
    if "reflection" in err or "dunder" in err or "getattr" in err:
        return "reflection (__dict__/setattr)"
    if "unauthorized call root" in err or "unrecognized free call" in err:
        return "third-party library not injected"
    return "other (thread, file lock, etc.)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--n", type=int, default=200,
                    help="benign cells per seed (paper sets total 1834 across seeds)")
    args = ap.parse_args()

    print("=" * 78)
    print("RQ1: Manifest extraction & PyCap acceptance  (paper §4.4.1, Table 4.4a)")
    print("=" * 78)

    accepted, failures = 0, []
    cvm = CVM()
    n_effects: List[int] = []
    label_ceiling_counts: Dict[str, int] = {"BOT": 0, "H": 0}
    for s in range(args.seeds):
        for case in benign(s, args.n):
            try:
                syntax_filter(case.source)
                accepted += 1
            except PyCapSyntaxError as e:
                failures.append(_classify_failure(str(e)))
                continue
            res = cvm.submit_cell(CellSubmission(case.source, case.state_in))
            cvm.reset_session()
            if res.manifest:
                n_effects.append(len(res.manifest.effects))
                label_ceiling_counts[res.manifest.label_ceiling.name] += 1
    total = accepted + len(failures)
    p = accepted / total if total else 0.0
    lo, hi = wilson_ci(accepted, total)
    print(f"\nPyCap initial syntax-acceptance rate: {fmt_ci(p, lo, hi)}  ({accepted}/{total})")

    if failures:
        print("\nTable 4.4a — Failure root-cause breakdown:")
        from collections import Counter
        c = Counter(failures)
        for cause, count in c.most_common():
            print(f"  {cause:35s}  {count*100/len(failures):5.1f}% ({count}/{len(failures)})")

    if n_effects:
        avg = sum(n_effects) / len(n_effects)
        print(f"\nManifest tightness:")
        print(f"  mean |E_t| (effects per cell) : {avg:5.2f}")
        print(f"  label_ceiling distribution    : BOT={label_ceiling_counts['BOT']}"
              f"  H={label_ceiling_counts['H']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
