#!/usr/bin/env python3
"""SovereignSec-AI — ablation-ladder runner (PLAN.md §8.1).

Builds each requested rung, evaluates it on the chosen set, and prints the
ablation table with the delta vs the SAST-tool-alone baseline. Unimplemented
rungs are reported as `pending (Phase 1)` rather than crashing, so this runs on
day 1 and the ladder fills in over the project.

    python run_baseline.py --model Qwen/Qwen2.5-Coder-7B-Instruct --rungs 0,2 --set owasp_benchmark
"""
from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from sscai_eval import datasets
from sscai_eval.metrics import DetectionScore, delta_vs_baseline, score_detection
from sscai_eval.pipeline import build_pipeline
from sscai_eval.rungs import BASELINE_RUNG, RUNG_DESCRIPTIONS, Rung, parse_rungs


def evaluate_rung(rung: Rung, model: str, items) -> DetectionScore | None:
    """Run one rung over all items; return aggregate detection score, or None if pending."""
    auditor = build_pipeline(rung, model)
    agg = DetectionScore(0, 0, 0)
    try:
        for item in items:
            s = score_detection(auditor.audit(item), item.ground_truth_keys)
            agg.tp += s.tp
            agg.fp += s.fp
            agg.fn += s.fn
    except NotImplementedError as e:
        Console().print(f"[yellow]rung {int(rung)} ({rung.name}): pending — {e}[/]")
        return None
    return agg


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--rungs", default="0,2", help="comma-separated, e.g. 0,1,2,3,4")
    ap.add_argument("--set", dest="eval_set", default="owasp_benchmark")
    args = ap.parse_args()

    console = Console()
    rungs = parse_rungs(args.rungs)

    try:
        items = datasets.load(args.eval_set)
    except NotImplementedError as e:
        console.print(f"[yellow]eval set '{args.eval_set}' not built yet — {e}[/]")
        console.print("Build it in PHASE0_CHECKLIST.md step 6, then re-run.")
        return 0

    scores: dict[Rung, DetectionScore] = {}
    for rung in rungs:
        s = evaluate_rung(rung, args.model, items)
        if s is not None:
            scores[rung] = s

    baseline = scores.get(BASELINE_RUNG)

    table = Table(title=f"SovereignSec-AI ablation — {args.model} on {args.eval_set}")
    for col in ("rung", "capability", "precision", "recall", "F1", "ΔF1 vs SAST"):
        table.add_column(col)
    for rung in rungs:
        s = scores.get(rung)
        if s is None:
            table.add_row(str(int(rung)), RUNG_DESCRIPTIONS[rung], "—", "—", "pending", "—")
            continue
        d = delta_vs_baseline(s, baseline)["f1"] if baseline else None
        table.add_row(
            str(int(rung)),
            RUNG_DESCRIPTIONS[rung],
            f"{s.precision:.3f}",
            f"{s.recall:.3f}",
            f"{s.f1:.3f}",
            f"{d:+.3f}" if d is not None else "—",
        )
    console.print(table)
    console.print("[dim]Reminder: the robust signal is ΔF1 vs the SAST-only baseline (PLAN §8.3).[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
