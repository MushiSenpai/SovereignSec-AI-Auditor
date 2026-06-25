#!/usr/bin/env python3
"""SovereignSec-AI — Blackwell environment verification gate.

Run this FIRST, before any training or eval (PHASE0_CHECKLIST.md step 3).
It fails loudly if the toolchain is wrong for an RTX 5090 (Blackwell, sm_120).
A bad Blackwell toolchain produces *silent garbage*, not errors — so we check
the runtime explicitly instead of trusting that `import torch` succeeding means
things are fine.

Exit code 0 = good to go. Non-zero = DO NOT PROCEED.

Maps to PLAN.md §2.4.
"""
from __future__ import annotations

import re
import subprocess
import sys
from typing import Optional, Tuple

CHECKS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))


def _ge(version: str, minimum: Tuple[int, ...]) -> bool:
    """True if dotted `version` >= `minimum` tuple (ignores trailing suffixes)."""
    nums = re.findall(r"\d+", version or "")
    parsed = tuple(int(x) for x in nums[: len(minimum)])
    return parsed >= minimum


def _driver_cuda_version() -> Optional[Tuple[int, int]]:
    """Parse the 'CUDA Version: X.Y' the driver reports in `nvidia-smi`."""
    try:
        out = subprocess.run(
            ["nvidia-smi"], capture_output=True, text=True, timeout=15
        ).stdout
    except Exception:
        return None
    m = re.search(r"CUDA Version:\s*(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def main() -> int:
    # --- torch import ---
    try:
        import torch
    except Exception as e:  # noqa: BLE001
        record("import torch", False, repr(e))
        return _report()

    record("torch import", True, torch.__version__)

    # --- torch built for cu128 (Blackwell requires it) ---
    built = torch.version.cuda  # e.g. "12.8"
    record(
        "torch built for CUDA 12.8 (cu128)",
        bool(built) and built.startswith("12.8"),
        f"torch.version.cuda={built!r} — Blackwell needs a cu128 wheel",
    )

    # --- CUDA visible + Blackwell sm_120 ---
    record("CUDA available", torch.cuda.is_available(), "")
    if torch.cuda.is_available():
        cap = torch.cuda.get_device_capability(0)
        record(
            "GPU is Blackwell sm_120",
            cap == (12, 0),
            f"compute capability={cap} — RTX 5090 == (12, 0)",
        )
        props = torch.cuda.get_device_properties(0)
        total_gb = props.total_memory / 1024**3
        record("GPU detected", True, f"{torch.cuda.get_device_name(0)} · {total_gb:.1f} GiB")
        record("≈32 GB VRAM", total_gb >= 30.0, f"{total_gb:.1f} GiB")

    # --- the CUDA 13.2 'gibberish' landmine (RUNTIME, not driver) ---
    # The Unsloth warning targets the CUDA runtime/toolkit (13.2), not the driver max.
    # A cu128 torch build bundles a 12.8 runtime, so a 13.2 *driver* is fine (a newer
    # driver runs an older runtime). Hard-fail only on a 13.2 *runtime*; a 13.2 driver
    # with a safe runtime is a pass-with-note (still smoke-test output empirically).
    runtime_132 = bool(built) and built.startswith("13.2")
    record("CUDA runtime (torch) is not 13.2", not runtime_132,
           f"torch runtime CUDA={built!r} — the runtime, not the driver, triggers gibberish")
    drv = _driver_cuda_version()
    if drv == (13, 2) and not runtime_132:
        record("driver CUDA 13.2 (runtime overrides)", True,
               "driver max-CUDA is 13.2 but torch uses its bundled cu128 runtime → OK; "
               "still confirm output isn't gibberish via a smoke train/inference")
    elif drv is not None:
        record("driver CUDA reported", True, f"{drv[0]}.{drv[1]}")

    # --- triton >= 3.3.1 ---
    try:
        import triton

        record("triton >= 3.3.1", _ge(triton.__version__, (3, 3, 1)), triton.__version__)
    except Exception as e:  # noqa: BLE001
        record("import triton", False, repr(e))

    # --- bitsandbytes (4-bit QLoRA) ---
    try:
        import bitsandbytes as bnb

        record("import bitsandbytes", True, getattr(bnb, "__version__", "?"))
    except Exception as e:  # noqa: BLE001
        record("import bitsandbytes", False, repr(e))

    # --- unsloth ---
    try:
        from unsloth import FastLanguageModel  # noqa: F401

        record("import unsloth.FastLanguageModel", True, "")
    except Exception as e:  # noqa: BLE001
        record("import unsloth", False, repr(e))

    return _report()


def _report() -> int:
    width = max((len(n) for n, _, _ in CHECKS), default=10)
    print("\nSovereignSec-AI — Blackwell environment gate\n" + "=" * 52)
    failed = 0
    for name, ok, detail in CHECKS:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        line = f"[{mark}] {name.ljust(width)}"
        if detail:
            line += f"  · {detail}"
        print(line)
    print("=" * 52)
    if failed:
        print(f"\n{failed} check(s) FAILED — fix the toolchain before proceeding.\n")
        return 1
    print("\nAll checks passed. Environment is Blackwell-ready.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
