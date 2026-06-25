"""The ablation ladder (PLAN.md §8.1) — the headline table of the case study.

Each rung adds exactly one capability so we can attribute the delta. The robust
comparison is always *vs the SAST-tool-alone baseline* (rung 2), which is immune
to "the base model already memorized the CVE" (PLAN §8.3).
"""
from __future__ import annotations

from enum import IntEnum


class Rung(IntEnum):
    BASE = 0          # base model, bare prompt — the floor
    RETRIEVAL = 1     # + graph-aware retrieval (L1/L2)
    SAST = 2          # + deterministic SAST (L3, Semgrep OSS + own rules)
    AGENT = 3         # + agentic loop (L4)
    VALIDATION = 4    # + validation (L5, static + dynamic)
    FINETUNE = 5      # + fine-tuned model swapped in — the adapter's honest contribution


RUNG_DESCRIPTIONS: dict[Rung, str] = {
    Rung.BASE: "base model, bare prompt",
    Rung.RETRIEVAL: "+ graph-aware retrieval",
    Rung.SAST: "+ deterministic SAST (tool-only baseline)",
    Rung.AGENT: "+ agentic loop",
    Rung.VALIDATION: "+ validation (static + dynamic)",
    Rung.FINETUNE: "+ fine-tuned model",
}

BASELINE_RUNG = Rung.SAST  # the delta-vs-baseline anchor


def parse_rungs(spec: str) -> list[Rung]:
    """'0,2,3' -> [Rung.BASE, Rung.SAST, Rung.AGENT]."""
    out: list[Rung] = []
    for tok in spec.split(","):
        tok = tok.strip()
        if tok:
            out.append(Rung(int(tok)))
    return out
