"""Structured finding contract — what the auditor must emit (PLAN.md §3 report).

Keeping this strict is also one of the three honest jobs of the fine-tune
(PLAN.md §1): the model must produce schema-valid findings so the agent loop
and validators run deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(str, Enum):
    """Set by L5 (validation). REFUTED findings are dropped from the report."""

    UNVALIDATED = "unvalidated"
    STATIC_CONFIRMED = "static_confirmed"      # re-scan / second tool agrees
    DYNAMIC_CONFIRMED = "dynamic_confirmed"    # exploit oracle fired pre-patch, gone post-patch
    REFUTED = "refuted"                        # could not be reproduced → false positive


@dataclass
class Finding:
    cwe_id: str                                # e.g. "CWE-89"
    severity: Severity
    file: str
    line: int
    title: str
    dataflow_trace: list[str] = field(default_factory=list)  # source → … → sink
    patch: Optional[str] = None                # unified diff
    confidence: float = 0.0                    # 0..1, calibrated (PLAN §1)
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    rationale: str = ""

    def key(self) -> tuple[str, str, int]:
        """Identity for dedup / matching against ground truth (file:line:cwe)."""
        return (self.file, self.cwe_id, self.line)
