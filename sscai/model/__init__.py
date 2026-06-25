"""Serving glue: vLLM launch config + the verified model IDs/constants (IMPL_SPEC §4).

Verification corrections baked in (these OVERRIDE the drafts):
  - Model ID is `mistralai/Devstral-Small-2-24B-Instruct-2512` — the `-2512` suffix
    is PART of the ID (without it, offline pre-download targets nothing).
  - `Devstral-Small-2505` is a DIFFERENT (May-2025) generation, not a BF16 build
    of 2512. BF16 24B (~48GB) won't fit 32GB → FP8/quantized is MANDATORY for serving.
  - 256K native context; --max-model-len is a VRAM BUDGET choice, not a model limit.
  - Structured output: per-request key is `structured_outputs` (vLLM v0.12+);
    `guided_json`/`guided_decoding_backend` were REMOVED. Backend is a server-start
    flag only: --structured-outputs-config.backend xgrammar.
  - Qwen2.5-Coder native tool-calling is a trap (--tool-call-parser hermes fails on
    the Coder variant) → use structured/guided decoding as the universal path.
"""
from __future__ import annotations

DEVSTRAL = "mistralai/Devstral-Small-2-24B-Instruct-2512"   # default; FP8; Apache-2.0
QWEN_CODER_32B = "Qwen/Qwen2.5-Coder-32B-Instruct"          # reliable QLoRA fallback
QWEN_CODER_7B = "Qwen/Qwen2.5-Coder-7B-Instruct"            # fast proxy

# The action the agent must emit each step (constrained via structured_outputs).
ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {"type": "string", "enum": [
            "read_file", "ast_query", "grep", "run_semgrep",
            "run_tests", "propose_patch", "validate", "emit_finding", "finish"]},
        "args": {"type": "object"},
    },
    "required": ["thought", "tool", "args"],
}

# Final finding the agent emits (sink for emit_finding).
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "cwe": {"type": "string"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "title": {"type": "string"},
        "evidence": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": ["cwe", "severity", "file", "line", "title", "confidence"],
}
