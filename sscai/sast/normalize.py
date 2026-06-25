"""Normalize Semgrep + Bandit JSON into one candidate record (IMPL_SPEC §2).

A `Candidate` is a SAST *candidate sink* — NOT a confirmed finding. L4 triages
candidates (drops false positives, assesses cross-file exploitability) and only
then emits a `sscai_eval.schema.Finding`.

Verification corrections baked in (these OVERRIDE the original draft):
  - We compute our OWN stable fingerprint: Semgrep's extra.fingerprint returns the
    literal "requires login" placeholder when logged out (field-gated since
    v1.101.0). extra.lines is NOT gated, so it's safe for the fingerprint hash.
  - Bandit JSON has NO col_offset → we never set/advertise a Bandit column.
  - Dual severity map handles both legacy (ERROR/WARNING/INFO) and current
    (CRITICAL/HIGH/MEDIUM/LOW) Semgrep severity strings.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

# Maps both Semgrep severity vocabularies + Bandit's to our 3-level scale.
_SEV = {
    "ERROR": "high", "CRITICAL": "high", "HIGH": "high",
    "WARNING": "medium", "MEDIUM": "medium",
    "INFO": "low", "LOW": "low",
}

# Bandit test_id -> CWE (extend as rules grow). Bandit's issue_cwe.id is a NUMBER.
_BANDIT_CWE = {
    "B608": "CWE-89",   # hardcoded_sql_expressions (SQLi)
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B301": "CWE-502",  # pickle
    "B506": "CWE-20",   # yaml_load
    "B303": "CWE-327",  # weak crypto (md5/sha1)
}


def normalize_severity(raw: Optional[str]) -> str:
    return _SEV.get((raw or "").upper(), "medium")


def candidate_fingerprint(tool: str, rule: str, path: str, line: int, code: str) -> str:
    """Stable local fingerprint (IMPL_SPEC §2 — do NOT use Semgrep's gated one)."""
    return hashlib.sha256(f"{tool}|{rule}|{path}|{line}|{code}".encode()).hexdigest()[:16]


@dataclass
class Candidate:
    tool: str                       # "semgrep" | "bandit"
    rule_id: str
    path: str
    line: int
    severity: str                   # high | medium | low
    message: str
    code: str = ""
    end_line: Optional[int] = None
    col: Optional[int] = None       # never set for bandit
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    taint_trace: Optional[list] = None
    autofix: Optional[str] = None
    confidence: Optional[str] = None  # bandit issue_confidence -> L4 triage prior
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = candidate_fingerprint(self.tool, self.rule_id, self.path, self.line, self.code)


def from_semgrep(result: dict) -> Candidate:
    extra = result.get("extra", {}) or {}
    meta = extra.get("metadata", {}) or {}
    start = result.get("start", {}) or {}
    cwe = meta.get("cwe", [])
    return Candidate(
        tool="semgrep",
        rule_id=result.get("check_id", "?"),
        path=result.get("path", "?"),
        line=int(start.get("line", 0)),
        col=start.get("col"),
        end_line=(result.get("end", {}) or {}).get("line"),
        severity=normalize_severity(extra.get("severity")),
        message=extra.get("message", ""),
        code=(extra.get("lines", "") or "")[:400],   # extra.lines is NOT login-gated
        cwe=cwe if isinstance(cwe, list) else [cwe],
        owasp=meta.get("owasp", []) if isinstance(meta.get("owasp", []), list) else [meta.get("owasp")],
        taint_trace=extra.get("dataflow_trace"),
        autofix=extra.get("fix"),
    )


def from_bandit(result: dict) -> Candidate:
    test_id = result.get("test_id", "?")
    cwe_obj = result.get("issue_cwe") or {}
    cwe_id = cwe_obj.get("id")  # numeric (or None before bandit 1.7.3)
    cwe = [f"CWE-{cwe_id}"] if cwe_id is not None else ([_BANDIT_CWE[test_id]] if test_id in _BANDIT_CWE else [])
    return Candidate(
        tool="bandit",
        rule_id=test_id,
        path=result.get("filename", "?"),
        line=int(result.get("line_number", 0)),
        col=None,                                     # IMPL_SPEC §2: bandit has no col_offset
        severity=normalize_severity(result.get("issue_severity")),
        message=result.get("issue_text", ""),
        code=(result.get("code", "") or "")[:400],
        cwe=cwe,
        confidence=result.get("issue_confidence"),
    )
