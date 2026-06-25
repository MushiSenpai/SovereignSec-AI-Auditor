"""Per-rung pipeline factory (PLAN.md §3 architecture, §8.1 ladder).

This file defines the *contracts* — the `Auditor` protocol and the five system
layers — and a factory that composes them per rung. The layer bodies are Phase-1
work (PLAN §9); here they are typed stubs so the shape is locked and Phase 1 is a
fill-in-the-blanks exercise. `build_pipeline` never silently no-ops: an unbuilt
layer raises NotImplementedError, which `run_baseline.py` catches and reports as
`pending`.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .rungs import Rung
from .schema import Finding


@runtime_checkable
class Auditor(Protocol):
    def audit(self, item) -> list[Finding]:  # item: datasets.EvalItem
        ...


# --- system layers (L1–L5). Implement in Phase 1, one per rung. ---------------

class RepoGraph:
    """L1: tree-sitter AST → call/import/dataflow graph + symbol table (CPU)."""

    def build(self, repo_path: str):
        raise NotImplementedError("Phase 1: L1 repo-graph (PLAN §3)")


class GraphRetriever:
    """L2: walk callers/callees/taint-neighbors + CWE/CVE pattern DB. Embeddings = fallback only."""

    def retrieve(self, graph, target) -> list[str]:
        raise NotImplementedError("Phase 1: L2 graph retrieval (PLAN §3)")


class SemgrepRunner:
    """L3: deterministic SAST. Semgrep OSS engine + OUR OWN rules (license: PLAN §3/§12)."""

    def candidates(self, repo_path: str) -> list[Finding]:
        raise NotImplementedError("Phase 0/1: SAST baseline — implement first (no LLM)")


class AgentLoop:
    """L4: LLM orchestrates hypothesis → trace → tool calls → exploitability → patch."""

    def investigate(self, item, evidence, candidates) -> list[Finding]:
        raise NotImplementedError("Phase 1: L4 agent loop (PLAN §3)")


class Validator:
    """L5: static re-scan + dynamic oracle (Juice Shop API / DVWA levels), pinned digests, N repeats."""

    def validate(self, item, findings) -> list[Finding]:
        raise NotImplementedError("Phase 1: L5 validation (PLAN §8.4)")


class ModelBackend:
    """The LLM (base or fine-tuned), served via vLLM. rung 5 swaps the adapter in."""

    def __init__(self, model: str, finetuned: bool = False):
        self.model = model
        self.finetuned = finetuned

    def bare_audit(self, item) -> list[Finding]:
        raise NotImplementedError("Phase 0: rung-0 bare-LLM audit — implement first")


# --- the composed, rung-gated auditor ----------------------------------------

class AblationAuditor:
    """Composes only the layers enabled at `rung`. Higher rungs = more layers."""

    def __init__(self, rung: Rung, model: str):
        self.rung = rung
        self.model = ModelBackend(model, finetuned=(rung >= Rung.FINETUNE))
        self.graph = RepoGraph() if rung >= Rung.RETRIEVAL else None
        self.retriever = GraphRetriever() if rung >= Rung.RETRIEVAL else None
        self.sast = SemgrepRunner() if rung >= Rung.SAST else None
        self.agent = AgentLoop() if rung >= Rung.AGENT else None
        self.validator = Validator() if rung >= Rung.VALIDATION else None

    def audit(self, item) -> list[Finding]:
        # Phase 0 implements the two no-scaffolding paths (BASE, SAST). The rest
        # are wired here in Phase 1 as each layer lands.
        if self.rung == Rung.BASE:
            return self.model.bare_audit(item)
        if self.rung == Rung.SAST:
            return self.sast.candidates(item.repo_path)  # tool-only baseline (no LLM)
        raise NotImplementedError(
            f"rung {int(self.rung)} ({self.rung.name}) pending — Phase 1 (PLAN §9)"
        )


def build_pipeline(rung: Rung, model: str) -> Auditor:
    return AblationAuditor(rung=rung, model=model)
