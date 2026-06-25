"""SovereignSec-AI — the air-gapped agentic code-security auditor (core product).

Layers (see PHASE1_DESIGN.md §3, IMPL_SPEC.md):
  graph/      L1 — tree-sitter parse + Jedi resolution + custom inter-proc taint
  retrieval/  L2 — graph-walk evidence assembly
  sast/       L3 — Semgrep CE + Bandit deterministic candidate finder (ships our rules only)
  agent/      L4 — raw ReAct loop over local vLLM (structured outputs)
  validation/ L5 — deterministic offline oracle stack (N-run unanimity)
  model/      serving glue (vLLM + LoRA registry, prompt/schema constants)

Everything runs with ZERO network egress at runtime (IMPL_SPEC "Offline guarantees").
"""

__all__ = []
