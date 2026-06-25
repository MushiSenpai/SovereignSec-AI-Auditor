"""Benchmark primitives — time, accuracy, environment (so everything is measurable).

Used by bench_pipeline.py (L1-L5 latency + accuracy) and bench_train.py (VRAM,
tokens/sec, train time). Reports are JSON (machine) + Markdown (human), both committed
as portfolio artifacts.
"""
from __future__ import annotations

import json
import platform
import re
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class TimingResult:
    label: str
    runs: int
    min_s: float
    median_s: float
    mean_s: float
    max_s: float
    samples: list = field(default_factory=list)


def timeit(label: str, fn: Callable, repeats: int = 5, warmup: int = 1) -> TimingResult:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return TimingResult(label=label, runs=repeats, min_s=round(min(samples), 4),
                        median_s=round(statistics.median(samples), 4),
                        mean_s=round(statistics.mean(samples), 4),
                        max_s=round(max(samples), 4),
                        samples=[round(s, 4) for s in samples])


def gpu_info() -> dict:
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.used,driver_version",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15).stdout.strip()
        name, total, used, drv = [x.strip() for x in out.split(",")]
        cuda = re.search(r"CUDA Version:\s*([\d.]+)",
                         subprocess.run(["nvidia-smi"], capture_output=True, text=True).stdout)
        return {"name": name, "vram_total_mib": int(total), "vram_used_mib": int(used),
                "driver": drv, "cuda_driver": cuda.group(1) if cuda else None}
    except Exception as e:  # noqa: BLE001
        return {"error": repr(e)}


def env_info() -> dict:
    vers = {}
    for m in ["tree_sitter", "tree_sitter_python", "jedi", "networkx", "bandit", "semgrep",
              "torch", "unsloth", "trl", "peft", "bitsandbytes", "transformers"]:
        try:
            mod = __import__(m)
            vers[m] = getattr(mod, "__version__", "?")
        except Exception:
            vers[m] = None
    return {"python": sys.version.split()[0], "platform": platform.platform(),
            "packages": vers}


def write_report(payload: dict, json_path: str, md_path: str, md_body: str) -> None:
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    Path(json_path).write_text(json.dumps(payload, indent=2, default=lambda o: asdict(o)
                                          if hasattr(o, "__dataclass_fields__") else str(o)))
    Path(md_path).write_text(md_body)
