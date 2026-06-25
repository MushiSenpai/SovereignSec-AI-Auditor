"""Tests for the real (non-stub) metric implementations (PLAN.md §8.2)."""
from __future__ import annotations

from sscai_eval.metrics import (
    DetectionScore,
    delta_vs_baseline,
    pass_at_k,
    patch_validation_rate,
    score_detection,
)
from sscai_eval.schema import Finding, Severity, ValidationStatus


def _finding(file: str, cwe: str, line: int, status=ValidationStatus.UNVALIDATED) -> Finding:
    return Finding(cwe_id=cwe, severity=Severity.HIGH, file=file, line=line,
                   title="t", validation_status=status)


def test_detection_perfect():
    gt = {("a.py", "CWE-89", 10), ("b.py", "CWE-79", 20)}
    preds = [_finding("a.py", "CWE-89", 10), _finding("b.py", "CWE-79", 20)]
    s = score_detection(preds, gt)
    assert (s.tp, s.fp, s.fn) == (2, 0, 0)
    assert s.precision == 1.0 and s.recall == 1.0 and s.f1 == 1.0


def test_detection_mixed():
    gt = {("a.py", "CWE-89", 10), ("b.py", "CWE-79", 20)}
    preds = [_finding("a.py", "CWE-89", 10), _finding("c.py", "CWE-22", 5)]  # 1 TP, 1 FP, 1 FN
    s = score_detection(preds, gt)
    assert (s.tp, s.fp, s.fn) == (1, 1, 1)
    assert s.precision == 0.5 and s.recall == 0.5 and abs(s.f1 - 0.5) < 1e-9


def test_empty_scores_are_zero_not_crash():
    s = DetectionScore(0, 0, 0)
    assert s.precision == 0.0 and s.recall == 0.0 and s.f1 == 0.0


def test_pass_at_k():
    assert pass_at_k(n=5, c=0, k=1) == 0.0      # never correct
    assert pass_at_k(n=5, c=5, k=1) == 1.0      # always correct
    assert pass_at_k(n=5, c=5, k=3) == 1.0
    # n=5, c=1, k=1 -> 1 - C(4,1)/C(5,1) = 1 - 4/5 = 0.2
    assert abs(pass_at_k(5, 1, 1) - 0.2) < 1e-9
    # n=5, c=1, k=5 -> n-c < k -> 1.0
    assert pass_at_k(5, 1, 5) == 1.0


def test_patch_validation_rate_counts_only_dynamic_confirmed():
    findings = [
        _finding("a.py", "CWE-89", 1, ValidationStatus.DYNAMIC_CONFIRMED),
        _finding("a.py", "CWE-89", 2, ValidationStatus.STATIC_CONFIRMED),  # not counted
        _finding("a.py", "CWE-89", 3, ValidationStatus.UNVALIDATED),
    ]
    assert abs(patch_validation_rate(findings) - (1 / 3)) < 1e-9
    assert patch_validation_rate([]) == 0.0


def test_delta_vs_baseline():
    baseline = DetectionScore(tp=1, fp=1, fn=1)   # F1 = 0.5
    better = DetectionScore(tp=2, fp=0, fn=0)     # F1 = 1.0
    d = delta_vs_baseline(better, baseline)
    assert abs(d["f1"] - 0.5) < 1e-9
    assert abs(d["precision"] - 0.5) < 1e-9
