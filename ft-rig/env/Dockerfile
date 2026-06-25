# SovereignSec-AI — pinned Blackwell (RTX 5090 / sm_120) training + eval image.
#
# Unsloth's official image already ships a Blackwell-correct stack: CUDA 12.8,
# a cu128 torch build, triton, and bitsandbytes cu128 wheels. We layer the eval
# harness + data-pipeline deps on top, constrained so nothing silently upgrades
# torch/triton/bnb off the Blackwell-correct versions.
#
# ⚠️ REPRODUCIBILITY: pin the digest on kickoff day (PHASE0_CHECKLIST.md step 2):
#   docker pull unsloth/unsloth:latest
#   docker inspect --format='{{index .RepoDigests 0}}' unsloth/unsloth:latest
# then replace the tag below with  unsloth/unsloth@sha256:<digest>.
# Until pinned, this tracks :latest and is NOT reproducible.
FROM unsloth/unsloth:latest

# Documents the hard constraint; CUDA 13.2 produces gibberish on Qwen3.6 (Unsloth docs).
LABEL org.sscai.cuda="12.8" \
      org.sscai.note="NEVER use CUDA 13.2 — gibberish on Qwen3.6"

WORKDIR /workspace
COPY constraints.txt /workspace/constraints.txt

# Eval-harness + data-pipeline deps, version-fenced by constraints.txt so the
# Blackwell-critical packages (torch/triton/bitsandbytes) are never moved.
RUN pip install --no-cache-dir -c /workspace/constraints.txt \
      transformers datasets peft trl accelerate \
      semgrep tree-sitter \
      pydantic rich pytest

# The rig (env scripts + eval package) lives here.
COPY . /workspace/ft-rig/env
ENV PYTHONPATH=/workspace/ft-rig/eval:${PYTHONPATH}

# Fail fast: a broken image should not start a training run — it should fail the gate.
CMD ["python", "/workspace/ft-rig/env/verify_env.py"]
