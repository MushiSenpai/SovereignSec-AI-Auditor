"""Evaluation metrics (PLAN.md §8.2). These are REAL implementations (tested) —
the harness's measurement core does not get to be a stub.

Detection: precision / recall / F1 against a labeled set, matched at file:line:cwe.
Repair:    pass@k (unbiased estimator) + patch-validation rate.
Reporting: always alongside the delta vs the tool-only baseline.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import comb
from typing import Iterable

from .schema import Finding, ValidationStatus


@dataclass
class DetectionScore:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score_detection(
    predicted: Iterable[Finding],
    ground_truth_keys: set[tuple[str, str, int]],
) -> DetectionScore:
    """Match predicted findings to ground-truth (file, cwe, line) keys."""
    pred_keys = {f.key() for f in predicted}
    tp = len(pred_keys & ground_truth_keys)
    fp = len(pred_keys - ground_truth_keys)
    fn = len(ground_truth_keys - pred_keys)
    return DetectionScore(tp=tp, fp=fp, fn=fn)


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k estimator (Chen et al. 2021): n samples, c correct."""
    if k <= 0 or n <= 0:
        return 0.0
    if c >= n:
        return 1.0
    if n - c < k:
        return 1.0
    return 1.0 - comb(n - c, k) / comb(n, k)


def patch_validation_rate(findings: Iterable[Finding]) -> float:
    """Fraction of *reported* findings whose patch was dynamically confirmed.

    Note (PLAN §8.2): only DYNAMIC_CONFIRMED counts as a real fix here — "tests
    pass" alone is a weak oracle. Use the full suite + differential tests upstream.
    """
    findings = list(findings)
    if not findings:
        return 0.0
    confirmed = sum(
        1 for f in findings if f.validation_status is ValidationStatus.DYNAMIC_CONFIRMED
    )
    return confirmed / len(findings)


def delta_vs_baseline(score: DetectionScore, baseline: DetectionScore) -> dict[str, float]:
    """F1/precision/recall lift over the tool-only baseline (the robust delta)."""
    return {
        "f1": score.f1 - baseline.f1,
        "precision": score.precision - baseline.precision,
        "recall": score.recall - baseline.recall,
    }
