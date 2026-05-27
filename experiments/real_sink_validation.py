"""§V.D — Real-sink closure validation (reviewer-requested addition).

Runs each of three real protocol sinks (network HTTP, ext4 export
directory, sqlite3 DB) with:

  * 5-10 sanctioned (Broker-mediated) commits per sink
  * 20-50 bypass attempts per variant per sink

Total per-sink scale: ~150 cases, ~300-400 cases overall. This is far
smaller than the 2,780 trajectories of the main benchmark and is meant
to *validate* (not replace) that the same commit-path closure holds
against real protocol implementations.

Run
---
    python -m experiments.real_sink_validation [--sanctioned N] [--bypass N]
Output
------
    results/table_real_sink_validation.csv
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from .common import write_csv, real_sink_bypass_rate
from .stats import clopper_pearson_upper

from .sinks import network_sink, file_sink, db_sink


SINKS = [
    ("Network (loopback HTTP)",        network_sink),
    ("File (atomic-rename export dir)", file_sink),
    ("DB (sqlite3 isolated file)",      db_sink),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Real-sink closure validation")
    ap.add_argument("--sanctioned", type=int, default=10,
                    help="Sanctioned commits per sink (paper: 5-10)")
    ap.add_argument("--bypass", type=int, default=30,
                    help="Bypass attempts per variant per sink (paper: 20-50)")
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    print("=" * 96)
    print("§V.D — Real-sink closure validation (HTTP / file / DB)")
    print("=" * 96)
    print(f"sanctioned commits / sink : {args.sanctioned}")
    print(f"bypass attempts / variant : {args.bypass}")

    rows = []
    summary_rows = []
    total_bypass_succ = 0
    total_bypass_attempts = 0

    for sink_label, sink_mod in SINKS:
        print(f"\n--- {sink_label} ---")
        res = sink_mod.run_sink(n_sanctioned=args.sanctioned,
                                 attempts_per_variant=args.bypass)
        s = res["sanctioned"]
        sanc_rate = s["committed"] / max(s["trials"], 1) * 100
        print(f"  sanctioned commits  : {s['committed']:>3}/{s['trials']:<3} "
              f"({sanc_rate:5.1f}%)   <- broker-mediated path, must succeed")

        print(f"  {'Bypass variant':<24}{'Succ':>8}{'Trials':>8}{'Rate':>10}{'95% UB':>12}")
        sink_succ = 0;  sink_trials = 0
        for variant, b in res["bypass"].items():
            ss = b["succeeded"];  tt = b["trials"]
            sink_succ   += ss
            sink_trials += tt
            rate = ss / max(tt, 1) * 100
            ub = clopper_pearson_upper(ss, max(tt, 1)) * 100
            print(f"  {variant:<24}{ss:>8}{tt:>8}{rate:>9.2f}%{ub:>11.2f}%")
            rows.append(dict(sink=sink_label, variant=variant,
                              successes=ss, trials=tt,
                              success_rate_pct=round(rate, 4),
                              upper_ci_95_pct=round(ub, 4)))

        sink_rate = sink_succ / max(sink_trials, 1) * 100
        sink_ub = clopper_pearson_upper(sink_succ, max(sink_trials, 1)) * 100
        print(f"  {'SINK TOTAL':<24}{sink_succ:>8}{sink_trials:>8}"
              f"{sink_rate:>9.2f}%{sink_ub:>11.2f}%")
        summary_rows.append(dict(
            sink=sink_label,
            sanctioned_committed=s["committed"],
            sanctioned_trials=s["trials"],
            bypass_successes=sink_succ,
            bypass_trials=sink_trials,
            bypass_rate_pct=round(sink_rate, 4),
            bypass_upper_ci_95_pct=round(sink_ub, 4),
        ))
        total_bypass_succ      += sink_succ
        total_bypass_attempts  += sink_trials

    grand_rate = total_bypass_succ / max(total_bypass_attempts, 1) * 100
    grand_ub = clopper_pearson_upper(total_bypass_succ,
                                       max(total_bypass_attempts, 1)) * 100
    print("\n" + "=" * 96)
    print(f"GRAND TOTAL Real-Sink Bypass Rate :"
          f"  {total_bypass_succ}/{total_bypass_attempts}"
          f"  =  {grand_rate:.2f}%   (Clopper-Pearson 95% UB {grand_ub:.2f}%)")
    print("\nPaper §V.D claim: each sink should report 0/N bypass; the test")
    print("validates that commit-path closure transfers from simulated to real sinks.")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table_real_sink_validation.csv")
    write_csv(csv_path, rows)
    summary_csv = os.path.join(args.out_dir, "table_real_sink_summary.csv")
    write_csv(summary_csv, summary_rows)
    print(f"\nPer-variant results : {csv_path}")
    print(f"Per-sink summary    : {summary_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
