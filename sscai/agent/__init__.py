"""L4 — raw ReAct audit loop over local vLLM (IMPL_SPEC §4).

Raw-Python loop (no LangChain): lightest, zero hidden telemetry, right trust model
for air-gap. The LLM ORCHESTRATES deterministic tools; it is never the scanner.
"""
from .context import AuditContext
from .loop import AuditAgent, VLLMBackend
from .tools import TOOLS, dispatch

__all__ = ["AuditAgent", "AuditContext", "VLLMBackend", "TOOLS", "dispatch"]
