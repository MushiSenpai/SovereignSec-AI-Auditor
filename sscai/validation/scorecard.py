"""OWASP-Benchmark-style scoring (IMPL_SPEC §5) — fully implemented + testable.

Used to validate our TP/FP/scoring MATH against a labeled corpus (Tier A). The
metric is the Youden index J = TPR - FPR (the OWASP Benchmark score), x100.

NOTE: OWASP Benchmark itself is Java — use it only to unit-test this math, never
to score our Python rules. For Python detection accuracy, feed Expected built
from our own labeled held-out set (PLAN §8).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Expected:
    name: str
    is_real: bool          # ground-truth: real vulnerability?
    category: str = ""
    cwe: str = ""


def score(expected: dict[str, Expected], flagged: set[str], category: str | None = None) -> dict:
    """expected: name -> Expected. flagged: set of names the tool reported."""
    tp = fp = fn = tn = 0
    for name, exp in expected.items():
        if category and exp.category != category:
            continue
        hit = name in flagged
        if exp.is_real and hit:
            tp += 1
        elif exp.is_real:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "tpr": round(tpr, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "youden_score": round((tpr - fpr) * 100, 2),
    }
