"""L3 — deterministic SAST candidate finder (Semgrep CE engine + Bandit).

Ships ONLY our own rules (IMPL_SPEC §2 licensing: the Semgrep registry rules are
under the restrictive Semgrep Rules License v1.0 and must not be distributed).
"""
from .normalize import Candidate, candidate_fingerprint, normalize_severity
from .runner import scan, run_semgrep, run_bandit

__all__ = ["Candidate", "scan", "run_semgrep", "run_bandit",
           "candidate_fingerprint", "normalize_severity"]
