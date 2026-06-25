"""Eval datasets (PLAN.md §8.2–§8.3, §7.2).

`EvalItem` is the unit of evaluation. Loaders are stubs wired in Phase-0 step 6.
Keep training and eval strictly separated; the Python-web held-out set must be
post-knowledge-cutoff, label-verified, contamination-filtered, and private/canaried.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class EvalItem:
    item_id: str
    repo_path: str                                   # local checkout (air-gapped)
    ground_truth_keys: set[tuple[str, str, int]] = field(default_factory=set)  # (file, cwe, line)
    gold_patch: Optional[str] = None                 # for repair eval + contamination probe
    cve_id: Optional[str] = None
    advisory_title: Optional[str] = None             # used by the contamination probe (no code)
    exploit_oracle: Optional[str] = None             # dynamic check id (Juice Shop challenge / DVWA level)
    is_private: bool = False                          # canaried, never published


# --- loader registry ----------------------------------------------------------

def load_owasp_benchmark() -> list[EvalItem]:
    """OWASP Benchmark — labeled TP/FP, the detector precision/recall anchor."""
    raise NotImplementedError("Phase 0 step 6: check out OWASP Benchmark (PLAN §8.2)")


def load_python_web_heldout() -> list[EvalItem]:
    """Post-cutoff GHSA PyPI advisories (Django/Flask/FastAPI), manually verified.
    PRIVATE + canaried — never published (PLAN §8.3, §11)."""
    raise NotImplementedError("Phase 0 step 6: build the post-cutoff Python-web set (PLAN §7.2)")


def load_swebench_verified() -> list[EvalItem]:
    """SWE-bench Verified — agentic-capability sanity check ONLY, not security.
    Note its contamination problems (PLAN §8.3)."""
    raise NotImplementedError("Phase 1: agentic-capability eval (PLAN §8.2)")


REGISTRY: dict[str, Callable[[], list[EvalItem]]] = {
    "owasp_benchmark": load_owasp_benchmark,
    "python_web_heldout": load_python_web_heldout,
    "swebench_verified": load_swebench_verified,
}


def load(name: str) -> list[EvalItem]:
    if name not in REGISTRY:
        raise KeyError(f"unknown eval set {name!r}; choose from {sorted(REGISTRY)}")
    return REGISTRY[name]()
