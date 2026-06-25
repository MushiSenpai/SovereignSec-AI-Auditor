"""Dynamic patch oracle (IMPL_SPEC §5) — the load-bearing Tier-D gate.

Verification corrections baked into the design (these OVERRIDE the draft):
  - SINGLE patched instance: apply-patch -> exploit -> func -> diff must all hit
    ONE patched container/derived image. The draft's bug applied the patch in a
    different fresh container than it exploited post-patch -> patch was lost.
  - --network=none blocks loopback BETWEEN containers: exploit client + target app
    must share a netns (same container via exec, or an internal no-gateway bridge).
    You cannot have two --network=none containers reach each other AND guarantee
    zero egress.
  - Assert explicit success/failure (a sentinel/solved-boolean), NOT process exit
    code (a crashed-but-exit-0 reads as a landed exploit).
  - Pin images by sha256 DIGEST (tags are mutable); fixed seeds / SOURCE_DATE_EPOCH.
  - N runs, UNANIMOUS-or-reject (never average — averaging hides a non-proof).

"Tests pass" is a partial oracle, never proof (ICSE-2026). The gate combines a
NEGATIVE oracle (exploit must now FAIL), behavior preservation (differential
golden tests), and metamorphic exploit variants.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OracleResult:
    verdict: str  # "FIXED" | "NOT_REAL" | "OVERFIT_OR_BROKEN" | "FLAKY_REJECT"
    detail: dict


def run_in_fresh_container(image_digest: str, exploit) -> bool:
    """Run the exploit against an unpatched fresh instance. True == exploit landed."""
    raise NotImplementedError("M2: digest-pinned `docker run`, --network=none after pull")


def run_patched_instance(image_digest: str, apply_patch, exploit, func, diff) -> dict:
    """In ONE patched instance: apply patch, re-exploit, run full suite + differential.

    Returns {"exploit": bool(landed_again), "func": bool(suite_green), "diff": bool(golden_ok)}.
    """
    raise NotImplementedError("M2: single-container apply->exploit->func->diff (IMPL_SPEC §5)")


def verify(image_digest: str, exploit, apply_patch, func, diff, n: int = 5) -> OracleResult:
    """N-run unanimous gate."""
    verdicts: list[str] = []
    for _ in range(n):
        if not run_in_fresh_container(image_digest, exploit):
            verdicts.append("NOT_REAL")
            continue
        post = run_patched_instance(image_digest, apply_patch, exploit, func, diff)
        ok = (not post["exploit"]) and post["func"] and post["diff"]
        verdicts.append("FIXED" if ok else "OVERFIT_OR_BROKEN")
    unanimous = len(set(verdicts)) == 1
    return OracleResult(
        verdict=verdicts[0] if unanimous else "FLAKY_REJECT",
        detail={"runs": verdicts},
    )
