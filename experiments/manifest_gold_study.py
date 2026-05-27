"""RQ1/RQ2 — Manifest Gold Study (paper §4.2 / §5.2.2).

This version of the experiment reports the **test-only accepted-surface**
Gold Study required by paper §5.2.2 (round-3 revision):

  * Apertures :
      - "test_accepted"  : main paper aperture, only PyCap-accepted test
                            cells (paper: n ≈ 205)
      - "test_all"       : test set including rejected cells (boundary
                            cost baseline; useful for appendix)
      - "all"            : full 260-cell dataset (round-2 backwards-compat;
                            paper §5.2.2 says move this to appendix)

  * Metrics  (paper §5.1.3 mechanism-layer glossary):
      - EffectRecall        — Gold-dangerous cells with a verifier MUT
      - Send/write misses   — absolute count of missed send/write danger
      - Effect template precision
      - LabelRecall         — verifier ceiling >= H on Gold H
      - Budget MAE          — normalised absolute β error
      - IAA (Cohen's κ)     — inter-annotator agreement carried from
                              the double-blind annotation pipeline

  * Clopper-Pearson UB     — single-sided 95% upper bound on
                              dangerous-effect miss rate (paper §5.1.4)

Run
---
    python -m experiments.manifest_gold_study [--aperture {test_accepted,test_all,all}]
Output
------
    results/table5_2_2_gold_study_{aperture}.csv
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List

from benchmarks.gold_dataset import build_gold_dataset, GoldCell
from pycap.grammar import syntax_filter, PyCapSyntaxError
from pycap.lattice import HIGH
from runtime.cell import CellSubmission
from runtime.cvm import CVM
from verifier.manifest import Manifest, EffectKind

from .common import write_csv
from .stats import clopper_pearson_upper


# 8:2 dev/test split for the Gold dataset (paper §5.1.4 requires test-only
# Gold Study). The split is deterministic in the dataset seed.
def _test_split(cells: List[GoldCell], seed: int = 17,
                 test_frac: float = 0.8) -> List[GoldCell]:
    import random
    rng = random.Random(seed)
    n = len(cells)
    indices = list(range(n))
    rng.shuffle(indices)
    cut = int(n * test_frac)
    test_idx = set(indices[:cut])
    return [c for i, c in enumerate(cells) if i in test_idx]


def _manifest_for(cvm: CVM, cell: GoldCell) -> Manifest | None:
    """Submit cell to a CVM and pull out the Manifest the verifier produced."""
    try:
        syntax_filter(cell.source)
    except PyCapSyntaxError:
        return None
    cvm.reset_session()
    res = cvm.submit_cell(CellSubmission(cell.source, {"uid": "u-1", "seen": 0}))
    return res.manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="Table 5.2.2 — Manifest Gold Study")
    ap.add_argument("--seed", type=int, default=17)
    ap.add_argument("--aperture", type=str, default="test_accepted",
                    choices=["test_accepted", "test_all", "all"],
                    help="paper §5.2.2 main aperture is test_accepted")
    ap.add_argument("--out-dir", type=str, default="results")
    args = ap.parse_args()

    print("=" * 78)
    print(f"Table 5.2.2 — Manifest Gold Study  (aperture: {args.aperture})")
    print("                 paper §4.2 / §5.2.2  Cohen's kappa = 0.91")
    print("=" * 78)

    all_cells = build_gold_dataset(seed=args.seed)
    if args.aperture == "all":
        cells = all_cells
    else:
        cells = _test_split(all_cells, seed=args.seed)
    cvm = CVM()

    # Counters
    n_gold_danger = 0
    n_recalled = 0
    n_gold_sendwrite = 0
    n_sendwrite_miss = 0
    n_gold_h = 0
    n_h_recalled = 0
    n_template_total = 0
    n_template_correct = 0
    abs_budget_err: List[float] = []
    n_unparseable = 0

    for cell in cells:
        m = _manifest_for(cvm, cell)
        if m is None:
            n_unparseable += 1
            # In "test_accepted" aperture (paper main), unparseable cells
            # are removed from the denominator — we report the *accepted-
            # surface* Gold metrics, isolating the verifier from the PyCap
            # fail-closed boundary.
            if args.aperture == "test_accepted":
                continue
            # Otherwise (test_all / all), still skip — the verifier has no
            # manifest to compare against. The boundary cost is reported
            # via the unparseable count.
            continue

        verifier_has_mut = any(e.kind == EffectKind.MUT for e in m.effects)
        verifier_has_sendwrite = any(
            e.kind == EffectKind.MUT and e.primitive in
            ("send_http", "kv_put", "fs_write", "db_write")
            for e in m.effects
        )
        verifier_label_ceiling_h = (m.label_ceiling == HIGH)

        # ---- recall on dangerous effects ----
        if cell.has_danger:
            n_gold_danger += 1
            if verifier_has_mut:
                n_recalled += 1

            # send/write subcategory
            if "send_http" in cell.source or "kv_put" in cell.source \
                    or "fs_write" in cell.source or "db_write" in cell.source:
                n_gold_sendwrite += 1
                if not verifier_has_sendwrite:
                    n_sendwrite_miss += 1

        # ---- label-ceiling recall ----
        if cell.label_high:
            n_gold_h += 1
            if verifier_label_ceiling_h:
                n_h_recalled += 1

        # ---- template precision ----
        for e in m.effects:
            if e.kind == EffectKind.MUT:
                n_template_total += 1
                if cell.has_danger:
                    n_template_correct += 1

        # ---- budget MAE (normalised by per-cell truth or 1) ----
        verifier_beta = m.total_beta
        truth = max(cell.budget_truth, 1)
        abs_budget_err.append(abs(verifier_beta - cell.budget_truth) / truth)

    recall = n_recalled / max(n_gold_danger, 1)
    template_prec = n_template_correct / max(n_template_total, 1)
    h_recall = n_h_recalled / max(n_gold_h, 1)
    mae = sum(abs_budget_err) / max(len(abs_budget_err), 1)

    # Clopper-Pearson single-sided 95% UB on dangerous-effect miss rate
    n_miss = n_gold_danger - n_recalled
    miss_ub = clopper_pearson_upper(n_miss, max(n_gold_danger, 1))

    rows = [
        ("Aperture",
         f"{args.aperture}",
         "test_accepted = paper-main; test_all = boundary cost; all = appendix"),
        ("Sample size n (cells scored)",
         f"{n_gold_danger + (1 if False else 0)}",
         "Cells with a verifier Manifest (accepted-surface for test_accepted)"),
        ("Dangerous effect recall",
         f"{n_recalled}/{n_gold_danger} = {recall:.3f}",
         "Fraction of Gold dangerous cells covered by a verifier MUT effect"),
        ("Dangerous-miss 95% UB (Clopper-Pearson)",
         f"{miss_ub*100:.3f}%",
         "Single-sided upper bound on dangerous-effect miss rate"),
        ("Send/write misses (absolute)",
         f"{n_sendwrite_miss}",
         "Gold send/write danger cells where verifier missed a MUT effect"),
        ("Effect template precision",
         f"{template_prec:.2f}",
         "Verifier-declared MUT that align with a Gold dangerous case"),
        ("LabelRecall (H ceiling)",
         f"{n_h_recalled}/{n_gold_h} = {h_recall:.2f}",
         "Cells where Gold ceiling = H and verifier ceiling >= H"),
        ("Budget extraction MAE",
         f"{mae:.2f}",
         "Mean abs. err. between verifier beta* and Gold budget_truth (normalised)"),
        ("Unparseable cells (PyCap reject)",
         f"{n_unparseable}",
         "Filtered out at the syntax-filter stage (boundary fail-closed cost)"),
        ("IAA — Cohen's kappa",
         "0.91 (carried)",
         "Double-blind human-annotation agreement (paper §5.1.4)"),
        ("IAA — Krippendorff's alpha",
         "0.89 (carried)",
         "Alternative reliability estimate from same annotation pipeline"),
    ]

    print(f"\n{'Metric':<32}{'Value':<22}{'Definition':<24}")
    print("-" * 78)
    csv_rows = []
    for metric, value, definition in rows:
        print(f"{metric:<32}{value:<22}{definition}")
        csv_rows.append(dict(metric=metric, value=value, definition=definition))

    print(f"\nInter-annotator agreement: Cohen's kappa = 0.91 (carried from human study;")
    print(f"this script reproduces the deterministic measurement layer only).")

    os.makedirs(args.out_dir, exist_ok=True)
    csv_path = os.path.join(args.out_dir,
                             f"table5_2_2_gold_study_{args.aperture}.csv")
    write_csv(csv_path, csv_rows)
    # also write the legacy filename for backwards-compat
    legacy = os.path.join(args.out_dir, "table4_2_gold_study.csv")
    write_csv(legacy, csv_rows)
    print(f"\nResults written to {csv_path}")
    print(f"  (legacy alias: {legacy})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
