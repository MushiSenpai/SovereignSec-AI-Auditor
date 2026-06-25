# SovereignSec-AI — cross-file localization (the headline)

5 multi-file apps; vuln flows routes.py → services.py → sink layer. SYSTEM = cross-file taint (whole call graph); PER-FILE = LLM audits each file alone.

| config | localization recall |
|---|---|
| PER-FILE LLM (blind to cross-file) | 1.00 |
| **SYSTEM (cross-file taint)** | **1.00** |
| HYBRID (system ∪ per-file) | 1.00 |

**per-file 1.00 → cross-file taint 1.00 (+0.00).** The cross-file taint is deterministic and carries the full source→sink path.

Per-app (per-file LLM / system):
- app0_db [CWE-89] db.py::run_user_query: Y / Y  [user_view -> lookup_user() [arg 0] @L21 -> run_user_query() [arg 0] @L15 -> run_user_query]
- app1_ops [CWE-78] ops.py::probe_host: Y / Y  [probe_view -> network_probe() [arg 0] @L21 -> probe_host() [arg 0] @L15 -> probe_host]
- app2_fetch [CWE-918] fetch.py::fetch_preview: Y / Y  [preview_view -> preview_link() [arg 0] @L21 -> fetch_preview() [arg 0] @L15 -> fetch_preview]
- app3_files [CWE-22] files.py::read_document: Y / Y  [doc_view -> open_doc() [arg 0] @L21 -> read_document() [arg 0] @L15 -> read_document]
- app4_cache [CWE-502] cache.py::restore_session: Y / Y  [session_view -> load_session() [arg 0] @L21 -> restore_session() [arg 0] @L15 -> restore_session]