# SovereignSec-AI — the auditor MVP. Deterministic, fully air-gapped core (no GPU, no model).
#   docker build -t sovereignsec .
#   docker run --rm --network=none -v "$PWD:/target:ro" sovereignsec audit /target
# The --network=none proves it: it finds vulnerabilities with zero egress.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
      tree-sitter==0.25.* tree-sitter-python==0.25.* jedi networkx \
      semgrep bandit pyyaml

WORKDIR /app
COPY sscai/ /app/sscai/
ENV PYTHONPATH=/app SEMGREP_ENABLE_VERSION_CHECK=0 HF_HUB_OFFLINE=1

ENTRYPOINT ["python", "-m", "sscai"]
CMD ["--help"]
