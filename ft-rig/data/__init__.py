"""M1 — the data moat (IMPL_SPEC §0 mined + §6 synthetic).

No off-the-shelf label-verified Python-web vuln set exists → assemble + verify.
Pipeline: mine (GHSA/CVEfixes) + generate (teacher) → VERIFY-gate → hygiene →
assemble into the canonical records (records.py) → SFT mix + private held-out.

NOTE: §0 (mining) pins are VERIFY-PENDING until the data-mining grounding re-run
completes (workflow wf_27a528da-613). §6 (synthetic) is workflow-verified.
"""
__all__ = []
