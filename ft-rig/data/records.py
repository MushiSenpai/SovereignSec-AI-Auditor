"""Canonical training-record shapes + mix assembly (IMPL_SPEC §6, §0).

Both mined (§0) and synthetic (§6) data emit these conversational records so they
assemble into one SFT mix. Three SFT objectives + an ORPO preference shape.

Verified facts baked in:
  - Records are OpenAI `messages` (carries tool_calls; matches Nemotron + Unsloth
    chat-template path). Train with assistant_only_loss / response-only masking.
  - Nemotron-SFT-SWE-v2 is MIXED-license -> filter per-row on row["license"] to the
    CC-BY-4.0 subset and attribute; never embed in the shipped product.
  - Teacher != student for synthetic generation (don't bake in the student's blind spots).
  - The runnable exploit is AUTHORITATIVE ground truth; Semgrep/Bandit corroborate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# IMPL_SPEC §6 — calibration polish, NOT pretrain: small + high-signal (~20k records).
MIX = {
    "taint_trace_audit": 0.45,    # verified synthetic (vuln) + mined positives
    "calibration_negative": 0.25,  # paired secure / no-finding (>= positives per CWE family)
    "agentic_trajectory": 0.20,    # 50/50 our-synth + Nemotron CC-BY-4.0
    "agentless_repair": 0.10,      # Nemotron
}
TARGET_TOTAL = 20_000
# Hard rules: negatives >= positives within each CWE family; cap any single CWE
# at <=12% of taint_trace_audit; generate ~2.5-3x target, expect 40-70% gate discard.


@dataclass
class Record:
    objective: str                              # key in MIX
    messages: list[dict]                        # [{role, content}|{role,tool_calls}]
    metadata: dict[str, Any] = field(default_factory=dict)
    # metadata: {cwe_seed_id, framework, gen_batch_ts, verified{semgrep,bandit,exploit},
    #            teacher, license}


def taint_trace_audit(context: str, reasoning: str, finding: dict, meta: dict) -> Record:
    """(a) assistant = source->sink->sanitizer reasoning + FINDING json."""
    return Record("taint_trace_audit", [
        {"role": "system", "content": "You are a security auditor. Trace taint and report findings as JSON."},
        {"role": "user", "content": context},
        {"role": "assistant", "content": reasoning + "\nFINDING: " + _json(finding)},
    ], meta)


def calibration_negative(context: str, reasoning: str, checked_cwe: list[str], meta: dict) -> Record:
    """(b) paired SECURE version -> the model must say 'no finding' (precision lever)."""
    no_finding = {"no_finding": True, "checked_cwe": checked_cwe,
                  "verified_by": ["semgrep:silent", "bandit:silent", "exploit:failed-as-expected"]}
    return Record("calibration_negative", [
        {"role": "system", "content": "You are a security auditor. Report 'no finding' when code is safe."},
        {"role": "user", "content": context},
        {"role": "assistant", "content": reasoning + "\nFINDING: " + _json(no_finding)},
    ], meta)


@dataclass
class Preference:
    """ORPO record: chosen = calibrated verdict, rejected = hallucinated/over-confident."""
    prompt: list[dict]
    chosen: list[dict]
    rejected: list[dict]


def _json(obj) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"))
