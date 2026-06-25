"""L5 — the 'prove it' layer (IMPL_SPEC §5).

A finding is real only if a deterministic offline oracle confirms it; a patch is
accepted only if the oracle flips exploit-success -> failure AND the functional
suite + differential tests still pass, unanimous across N runs.
"""
from .scorecard import Expected, score

__all__ = ["Expected", "score"]
