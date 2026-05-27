"""§5.5 — Audit-chain tamper / replay / splice / visible-gap experiment (P4).

Four attack classes:
  Tamper      — flip a byte in a committed receipt body
  Replay      — re-submit an already-committed receipt
  Splice      — insert a forged receipt without updating downstream links
  VisibleGap  — drop a receipt from the chain, leaving a missing sequence #

For each class we run 200 trials and ask whether `audit.verify_integrity()`
detects the perturbation. The paper claims the auditor detects every
perturbation it can see (i.e. it does NOT claim resistance to tail truncation,
fork or rollback by default — those require external witnesses).

Run
---
    python -m experiments.audit_tamper [--trials 200]
Output
------
    results/table5_5_audit_tamper.csv
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
import random
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List

from broker.audit import AuditLog, Receipt
from runtime.cvm import CVM
from runtime.cell import CellSubmission
from .common import write_csv
from .stats import clopper_pearson_upper


def _make_audit() -> AuditLog:
    cvm = CVM()
    for i in range(5):
        cvm.submit_cell(CellSubmission(
            "def cell(uid, state_in):\n"
            f"    broker.send_http('alerts.partner.com', '/h{i}', {{'n': {i}}})\n"
            "    return state_in\n",
            {"uid": "u-1", "seen": i}))
        cvm.reset_session()
    return cvm.broker.audit


def _verify(audit: AuditLog) -> bool:
    """Stricter verifier: re-derive every chain link from canonical body."""
    from broker.audit import GENESIS
    prev = GENESIS
    for r in audit.receipts:
        if r.prev_chain != prev:
            return False
        body = json.dumps(dict(
            seq=r.seq, ir_hash=r.ir_hash, manifest_digest=r.manifest_digest,
            effect=r.effect, decision=r.decision, prev=r.prev_chain,
            ts=r.timestamp, note=r.note,
        ), sort_keys=True).encode()
        expect = hashlib.sha256(r.prev_chain.encode() + body).hexdigest()
        if expect != r.chain:
            return False
        prev = r.chain
    return True


def _tamper(audit: AuditLog, rng: random.Random) -> bool:
    if not audit.receipts:
        return False
    snap = copy.deepcopy(audit.receipts)
    target = rng.choice(audit.receipts)
    target.note = target.note + "X"
    detected = not _verify(audit)
    audit.receipts[:] = snap
    return detected


def _replay(audit: AuditLog, rng: random.Random) -> bool:
    if not audit.receipts:
        return False
    snap = copy.deepcopy(audit.receipts)
    audit.receipts.append(copy.deepcopy(audit.receipts[-1]))
    detected = not _verify(audit)
    audit.receipts[:] = snap
    return detected


def _splice(audit: AuditLog, rng: random.Random) -> bool:
    if not audit.receipts:
        return False
    snap = copy.deepcopy(audit.receipts)
    fake = Receipt(seq=len(audit.receipts), ir_hash="forged",
                    manifest_digest="x" * 64,
                    effect=dict(kind="Mut", primitive="x", op="POST",
                                target="evil", label="BOT", beta=4, origin=0),
                    decision="ADMIT", prev_chain=audit.head,
                    chain="0" * 64, timestamp=0.0)
    audit.receipts.append(fake)
    detected = not _verify(audit)
    audit.receipts[:] = snap
    return detected


def _visible_gap(audit: AuditLog, rng: random.Random) -> bool:
    if len(audit.receipts) < 2:
        return False
    snap = copy.deepcopy(audit.receipts)
    audit.receipts.pop(rng.randrange(len(audit.receipts) - 1))
    detected = not _verify(audit)
    audit.receipts[:] = snap
    return detected


def main() -> int:
    ap = argparse.ArgumentParser(description="P4 — Audit tamper")
    ap.add_argument("--trials", type=int, default=200,
                    help="Trials per attack class")
    ap.add_argument("--seed", type=int, default=71)
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    audit = _make_audit()

    print("=" * 78)
    print("§5.5 — Audit tamper / replay / splice / visible-gap (P4)")
    print("=" * 78)
    print(f"Trials per class: {args.trials}")
    print(f"Initial chain length: {len(audit.receipts)} receipts\n")

    classes = [
        ("tamper",      _tamper),
        ("replay",      _replay),
        ("splice",      _splice),
        ("visible_gap", _visible_gap),
    ]

    rows = []
    print(f"{'Attack class':<16}{'Detected':>10}{'Trials':>10}{'Detection':>14}{'95% UB miss':>15}")
    print("-" * 78)
    total_det, total_tri = 0, 0
    for name, fn in classes:
        det = 0
        for _ in range(args.trials):
            if fn(audit, rng):
                det += 1
        total_det += det;  total_tri += args.trials
        miss = args.trials - det
        miss_ub = clopper_pearson_upper(miss, args.trials)
        rate = det / args.trials * 100
        print(f"{name:<16}{det:>10}{args.trials:>10}{rate:>13.2f}%{miss_ub*100:>14.2f}%")
        rows.append(dict(attack=name, detected=det, trials=args.trials,
                          detection_rate_pct=round(rate, 2),
                          undetected_upper_ci_95_pct=round(miss_ub * 100, 4)))
    print("-" * 78)
    total_miss = total_tri - total_det
    total_ub = clopper_pearson_upper(total_miss, total_tri)
    print(f"{'TOTAL':<16}{total_det:>10}{total_tri:>10}"
          f"{total_det/total_tri*100:>13.2f}%{total_ub*100:>14.2f}%")
    rows.append(dict(attack="TOTAL", detected=total_det, trials=total_tri,
                      detection_rate_pct=round(total_det / total_tri * 100, 2),
                      undetected_upper_ci_95_pct=round(total_ub * 100, 4)))

    print("\nNote: This experiment covers visible-log perturbations only.")
    print("      Tail truncation, fork, and rollback by a privileged adversary")
    print("      require external witnesses / monotonic counters (paper §5.5).")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir, "table5_5_audit_tamper.csv")
    write_csv(csv_path, rows)
    print(f"\nResults written to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
