"""Local-inference backend (M4) — runs the agent loop with a REAL model, no vLLM.

For the rungs-0->5 ablation we need actual model output (base vs fine-tuned). vLLM
serving is the production path; for a self-contained ablation we generate directly
via Unsloth (loaded once, 4-bit). Two entry points:
  - .complete(messages)  -> raw text  (used by direct/bare audits, rung 0)
  - .act(messages)       -> action dict (used by the agent loop, rung 5)
"""
from __future__ import annotations

import json
import re

_JSON = re.compile(r"\{.*\}", re.S)


def _parse_json(text: str):
    m = _JSON.search(text or "")
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        # tolerate trailing junk: try the first balanced object
        depth = 0
        for i, ch in enumerate(m.group(0)):
            depth += ch == "{"
            depth -= ch == "}"
            if depth == 0:
                try:
                    return json.loads(m.group(0)[: i + 1])
                except json.JSONDecodeError:
                    return None
    return None


class LocalInferenceBackend:
    def __init__(self, model_dir: str, max_seq_len: int = 4096):
        from unsloth import FastLanguageModel
        self.model, self.tok = FastLanguageModel.from_pretrained(
            model_dir, max_seq_length=max_seq_len, load_in_4bit=True, dtype=None)
        FastLanguageModel.for_inference(self.model)

    def complete(self, messages: list, max_new_tokens: int = 256) -> str:
        ids = self.tok.apply_chat_template(messages, add_generation_prompt=True,
                                           return_tensors="pt").to(self.model.device)
        out = self.model.generate(input_ids=ids, max_new_tokens=max_new_tokens,
                                  do_sample=False, use_cache=True,
                                  pad_token_id=self.tok.eos_token_id)
        return self.tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True)

    def act(self, messages: list) -> dict:
        nudge = messages + [{"role": "user", "content":
                             "Respond with ONE next action as JSON: "
                             '{"thought":"...","tool":"run_semgrep|run_taint|ast_query|read_file|emit_finding|finish","args":{}}'}]
        return _parse_json(self.complete(nudge, 200)) or {"tool": "finish", "args": {}}


def direct_audit(backend: LocalInferenceBackend, code: str, max_new_tokens: int = 300) -> list:
    """Rung-0 bare audit: one forward pass, no tools. Returns list of findings (dicts)."""
    msgs = [
        {"role": "system", "content":
         "You are a security auditor. Find OWASP/CWE vulnerabilities in the code and "
         'reply with JSON: {"findings":[{"cwe":"CWE-..","file":"..","line":N}]}. '
         'If none, reply {"findings":[]}.'},
        {"role": "user", "content": f"```python\n{code}\n```"},
    ]
    obj = _parse_json(backend.complete(msgs, max_new_tokens)) or {}
    return obj.get("findings", []) if isinstance(obj, dict) else []
