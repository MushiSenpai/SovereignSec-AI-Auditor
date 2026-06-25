"""Anti-self-deception: the gold-patch reproduction probe (PLAN.md §8.3).

The strongest documented eval pitfall is contamination — frontier models can
reproduce verbatim gold patches from just a CVE id/title (OpenAI retired
SWE-bench Verified over this, Feb 2026). If the *base* model can already produce
the fix, any "detection" of that CVE is recall of training data, not skill — so
the item must be excluded from the eval set.

Implement when a ModelBackend exists (Phase 0 step 6). Until then this is a stub.
"""
from __future__ import annotations

from typing import Iterable


def gold_patch_reproduction_probe(model, item, threshold: float = 0.8) -> bool:
    """True if `model` can reproduce item's gold fix from only its id/title/hint.

    Implementation sketch (Phase 0):
      1. Prompt the model with ONLY the CVE id + advisory title (no code).
      2. Ask for the fix/patch.
      3. Compare to the gold patch (normalized diff similarity or an LLM judge).
      4. Return True if similarity >= threshold  -> CONTAMINATED -> exclude.
    """
    raise NotImplementedError(
        "Phase 0 step 6: implement once a ModelBackend is available (PLAN §8.3)"
    )


def filter_contaminated(items: Iterable, model, threshold: float = 0.8) -> list:
    """Drop items the base model already memorized. Log how many were removed —
    silent truncation reads as 'clean set' when it isn't (PLAN §8.3)."""
    kept, dropped = [], 0
    for it in items:
        if gold_patch_reproduction_probe(model, it, threshold):
            dropped += 1
        else:
            kept.append(it)
    print(f"[contamination] kept {len(kept)}, dropped {dropped} (memorized by base model)")
    return kept
