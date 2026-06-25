"""Synthetic generation — teacher model emits vuln+secure+exploit cells (IMPL_SPEC §6).

GENERATE stage of generate-and-verify. A matrix of (framework × CWE × idiom ×
difficulty); each cell yields a runnable vulnerable slice + paired secure fix +
exploit PoC + pytest. The assistant TARGET later is the AUDIT (reasoning + finding),
never exploitation prose — vulnerable code is input context only (keeps it defensive).

Verified corrections baked in:
  - TEACHER != STUDENT (don't bake in the student's blind spots). Use a different
    model than the one being trained.
  - vLLM structured output: `response_format={"type":"json_schema",...}` (NOT the
    removed guided_json). `vllm serve <model>` endpoint.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

FRAMEWORKS = ["django", "flask", "fastapi"]
# OWASP Top 10:2025 anchor classes for Python web (extend as rules grow).
CWES = ["CWE-89", "CWE-79", "CWE-918", "CWE-78", "CWE-502", "CWE-22", "CWE-285"]
DIFFICULTY = ["obvious", "idiomatic", "cross-call"]

CELL_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable_code": {"type": "string"},
        "secure_code": {"type": "string"},
        "exploit": {"type": "string"},      # runnable PoC (pytest-style asserts)
        "pytest": {"type": "string"},        # functional test that must pass on both
        "explanation": {"type": "string"},
    },
    "required": ["vulnerable_code", "secure_code", "exploit", "pytest"],
}


@dataclass
class Cell:
    framework: str
    cwe: str
    idiom: str
    payload: dict = field(default_factory=dict)   # the generated CELL_SCHEMA object


def _prompt(framework: str, cwe: str, idiom: str) -> str:
    return (
        f"Produce a small, realistic {framework} code slice containing a {cwe} "
        f"vulnerability in {idiom} style, plus: a SECURE fixed version, a runnable "
        f"exploit PoC (asserts it triggers on the vulnerable version), and a pytest "
        f"functional test that passes on BOTH. Return JSON per the schema. The code "
        f"is a TEST FIXTURE only."
    )


def generate(teacher_model: str, student_model: str,
             base_url: str = "http://localhost:8000/v1"):
    """Yield Cells. Raises if teacher == student (would bake in blind spots)."""
    if teacher_model == student_model:
        raise ValueError("teacher must differ from student (IMPL_SPEC §6)")
    from openai import OpenAI
    client = OpenAI(base_url=base_url, api_key="EMPTY")
    for fw in FRAMEWORKS:
        for cwe in CWES:
            for idiom in DIFFICULTY:
                r = client.chat.completions.create(
                    model=teacher_model, temperature=0.7, max_tokens=2048,
                    messages=[{"role": "user", "content": _prompt(fw, cwe, idiom)}],
                    response_format={"type": "json_schema", "json_schema":
                                     {"name": "vuln_cell", "schema": CELL_SCHEMA}})
                try:
                    payload = json.loads(r.choices[0].message.content)
                except (json.JSONDecodeError, TypeError):
                    continue
                yield Cell(framework=fw, cwe=cwe, idiom=idiom, payload=payload)
