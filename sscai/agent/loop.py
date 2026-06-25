"""The ReAct audit loop (L4, IMPL_SPEC §4).

Backend-driven so it's testable without a GPU: any backend with `.act(messages) ->
action dict {thought, tool, args}` drives the loop. Production = `VLLMBackend`
(corrected structured-outputs API); tests inject a scripted mock.

The LLM ORCHESTRATES deterministic tools (L1/L3/L5); it is never the scanner.
"""
from __future__ import annotations

import json

from sscai.model import ACTION_SCHEMA, DEVSTRAL
from .context import AuditContext
from .tools import OBS_BUDGET, TOOLS, dispatch

SYSTEM = (
    "You are a security auditor. You ORCHESTRATE deterministic tools; you are not "
    "the scanner. Workflow: run_semgrep + run_taint to gather candidates, use "
    "ast_query/read_file to trace each across files, drop false positives (e.g. "
    "parameterized queries), emit_finding only when evidence supports it, then finish. "
    "Prefer 'no finding' over guessing."
)


class VLLMBackend:
    """Production backend — local vLLM via the OpenAI-compatible API (IMPL_SPEC §4).

    Corrected API: constrain the action with
        extra_body={"structured_outputs": {"json": ACTION_SCHEMA}}
    (the old guided_json was removed in vLLM v0.12).
    """

    def __init__(self, model: str = DEVSTRAL, base_url: str = "http://localhost:8000/v1"):
        self.model = model
        self.base_url = base_url

    def act(self, messages: list) -> dict:
        from openai import OpenAI
        client = OpenAI(base_url=self.base_url, api_key="EMPTY")
        r = client.chat.completions.create(
            model=self.model, messages=messages, temperature=0.1, max_tokens=1024,
            extra_body={"structured_outputs": {"json": ACTION_SCHEMA}},
        )
        return json.loads(r.choices[0].message.content)


class AuditAgent:
    def __init__(self, ctx: AuditContext, max_steps: int = 40):
        self.ctx = ctx
        self.max_steps = max_steps
        self.trace: list = []

    def run(self, backend, task: str) -> list:
        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": task}]
        for _ in range(self.max_steps):
            action = backend.act(messages)
            tool = action.get("tool", "finish")
            args = action.get("args", {}) or {}
            obs = dispatch(tool, args, self.ctx)
            self.trace.append({"action": action, "obs": obs[:200]})
            messages.append({"role": "assistant", "content": json.dumps(action)})
            messages.append({"role": "user", "content": f"[{tool}] {obs[:OBS_BUDGET]}"})
            if tool == "finish":
                break
        return self.ctx.findings
