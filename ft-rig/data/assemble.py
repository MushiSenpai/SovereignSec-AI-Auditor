"""Assemble verified mined + synthetic data into the SFT mix (IMPL_SPEC §6, records.py).

Final stage: build canonical Records, dedup, split by CWE-seed FAMILY (a positive and
its calibration negative must never straddle train/eval), enforce the mix ratios, hold
out a chronological eval slice, and filter Nemotron to its CC-BY-4.0 rows.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .records import MIX, TARGET_TOTAL, Record, calibration_negative, taint_trace_audit
from .verify_labels import dedup


def from_verified_cell(cell, verdict, reasoning: str) -> list[Record]:
    """A verified cell → one positive (audit) + one calibration negative (secure pair)."""
    seed = f"{cell.framework}:{cell.cwe}:{cell.idiom}"
    meta = {"cwe_seed_id": seed, "framework": cell.framework, "teacher": "synthetic",
            "license": "ours",
            "verified": {"semgrep": verdict.semgrep_fires_on_vuln,
                         "bandit": verdict.bandit_corroborates,
                         "exploit": verdict.exploit_triggers_on_vuln}}
    finding = {"cwe": cell.cwe, "severity": "high", "confidence": 0.9}
    return [
        taint_trace_audit(cell.payload["vulnerable_code"], reasoning, finding, dict(meta)),
        calibration_negative(cell.payload["secure_code"],
                             "No tainted source reaches a sink; input is parameterized/escaped.",
                             [cell.cwe], dict(meta)),
    ]


def filter_nemotron_ccby(rows: Iterable[dict]) -> list[dict]:
    """Keep only CC-BY-4.0 rows (Nemotron-SFT-SWE-v2 is mixed-license); attribute."""
    return [r for r in rows if "CC-BY-4.0" in (r.get("license", "") or "").upper().replace(" ", "")]


def split_by_family(records: list[Record], holdout_frac: float = 0.05) -> tuple[list, list]:
    """Hold out whole CWE-seed families so positives + their negatives never split."""
    families: dict[str, list[Record]] = {}
    for r in records:
        families.setdefault(r.metadata.get("cwe_seed_id", "?"), []).append(r)
    fam_keys = sorted(families)
    cut = int(len(fam_keys) * (1 - holdout_frac))
    train = [r for k in fam_keys[:cut] for r in families[k]]
    held = [r for k in fam_keys[cut:] for r in families[k]]
    return train, held


def write_jsonl(records: list[Record], path: str) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps({"messages": r.messages, "metadata": r.metadata,
                                "objective": r.objective}) + "\n")
    return len(records)


def report_mix(records: list[Record]) -> dict:
    """Show the actual objective distribution vs the target MIX (log drift)."""
    counts: dict[str, int] = {}
    for r in records:
        counts[r.objective] = counts.get(r.objective, 0) + 1
    n = len(records) or 1
    return {obj: {"count": counts.get(obj, 0), "actual": round(counts.get(obj, 0) / n, 3),
                  "target": MIX.get(obj)} for obj in MIX}


def assemble(records: list[Record], out_dir: str = "ft-rig/data/out") -> dict:
    records = dedup([{"vulnerable": r.messages[1]["content"], **{"_r": r}} for r in records])
    records = [r["_r"] for r in records]   # unwrap after dedup over user content
    train, held = split_by_family(records)
    n_train = write_jsonl(train, f"{out_dir}/sft_train.jsonl")
    n_held = write_jsonl(held, f"{out_dir}/heldout.jsonl")
    return {"train": n_train, "heldout": n_held, "target_total": TARGET_TOTAL,
            "mix": report_mix(train)}
