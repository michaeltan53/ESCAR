"""§5.4.1 / §5.5 — Worker physical-bypass directed test (P3).

The Worker is a sandboxed process that may *only* issue external effects
via the Broker proxy. This experiment runs 700 attempts in which a
hostile Worker tries to short-circuit the Broker and call a raw syscall
directly. With the kernel monitor (seccomp/eBPF) active, all attempts
must fail.

Paper §5.5 reports: 700 attempts, 0 successes, Clopper-Pearson upper
bound ≤ 0.43%.

Run
---
    python -m experiments.worker_bypass [--trials 700]
Output
------
    results/table5_5_worker_bypass.csv
"""
from __future__ import annotations
import argparse
import os
import random
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List

from kernel.enforcement import KernelMonitor, SyscallDenied
from .common import write_csv
from .stats import clopper_pearson_upper


BYPASS_VECTORS = [
    ("raw socket connect",      "connect"),
    ("socket()",                "socket"),
    ("raw_socket()",            "raw_socket"),
    ("tcp_connect()",           "tcp_connect"),
    ("open(/etc/secret)",       "open"),
    ("execve(/bin/sh)",         "execve"),
    ("fork+execve",             "fork"),
    ("sendto(...)",             "sendto"),
    ("ptrace(...)",             "ptrace"),
    ("mount(...)",              "mount"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="P3 — Worker physical bypass")
    ap.add_argument("--trials", type=int, default=700,
                    help="Total bypass attempts (paper uses 700)")
    ap.add_argument("--seed", type=int, default=43)
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    monitor = KernelMonitor.default()

    print("=" * 78)
    print("§5.5 — Worker physical bypass directed test (P3)")
    print("=" * 78)
    print(f"Trials: {args.trials}\n")

    per_vector = {label: [0, 0] for label, _ in BYPASS_VECTORS}  # [succ, total]

    for _ in range(args.trials):
        label, syscall = rng.choice(BYPASS_VECTORS)
        per_vector[label][1] += 1
        try:
            monitor.call(syscall)
            per_vector[label][0] += 1
        except SyscallDenied:
            pass

    total_succ = sum(s for s, _ in per_vector.values())
    total_trials = sum(t for _, t in per_vector.values())
    upper = clopper_pearson_upper(total_succ, total_trials)

    print(f"{'Vector':<30}{'Success':>10}{'Trials':>10}{'Rate':>10}{'95% UB':>12}")
    print("-" * 78)
    rows = []
    for label, (s, t) in per_vector.items():
        rate = s / max(t, 1) * 100
        ub = clopper_pearson_upper(s, max(t, 1)) * 100
        print(f"{label:<30}{s:>10}{t:>10}{rate:>9.2f}%{ub:>11.2f}%")
        rows.append(dict(vector=label, successes=s, trials=t,
                          success_rate_pct=round(rate, 4),
                          upper_ci_95_pct=round(ub, 4)))
    print("-" * 78)
    print(f"{'TOTAL':<30}{total_succ:>10}{total_trials:>10}"
          f"{(total_succ/total_trials)*100:>9.2f}%{upper*100:>11.2f}%")
    rows.append(dict(vector="TOTAL", successes=total_succ, trials=total_trials,
                      success_rate_pct=round(total_succ / total_trials * 100, 4),
                      upper_ci_95_pct=round(upper * 100, 4)))

    print(f"\nPaper claim: 0/700 successes; Clopper-Pearson <= 0.43%.")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table5_5_worker_bypass.csv")
    write_csv(csv_path, rows)
    print(f"\nResults written to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
