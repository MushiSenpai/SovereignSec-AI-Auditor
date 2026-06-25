# SovereignSec-AI — haystack localization (does the SYSTEM help the LLM?)

Label: **base32b**. Task: localize the vuln in a full file (~14 functions each, 15 files; 5×CWE-79, 10×CWE-89). Auditor = 32B; LLM-judge scores localization vs ground truth.

| config | localization accuracy |
|---|---|
| BARE (file only) | 0.07 |
| SYSTEM (+ SAST candidates) | 0.07 |

**System delta: 0.07 -> 0.07 (+0.00).**

Per-file:
- tests/queries/test_explain.py [CWE-89, 7 fns, 1 SAST cands]: bare=N system=N
- django/contrib/postgres/aggregates/general.py [CWE-89, 5 fns, 0 SAST cands]: bare=N system=N
- django/contrib/postgres/aggregates/mixins.py [CWE-89, 6 fns, 0 SAST cands]: bare=N system=N
- django/contrib/gis/db/models/aggregates.py [CWE-89, 8 fns, 0 SAST cands]: bare=N system=N
- tests/queries/test_q.py [CWE-89, 29 fns, 0 SAST cands]: bare=N system=N
- tests/expressions/test_queryset_values.py [CWE-89, 6 fns, 0 SAST cands]: bare=N system=N
- django/utils/http.py [CWE-79, 16 fns, 0 SAST cands]: bare=N system=N
- tests/regressiontests/utils/http.py [CWE-79, 5 fns, 0 SAST cands]: bare=N system=N
- tests/utils_tests/test_http.py [CWE-79, 11 fns, 0 SAST cands]: bare=N system=N
- tests/backends/base/test_operations.py [CWE-89, 35 fns, 0 SAST cands]: bare=N system=N
- tests/template_tests/tests.py [CWE-79, 16 fns, 0 SAST cands]: bare=N system=N
- django/contrib/postgres/fields/hstore.py [CWE-89, 11 fns, 0 SAST cands]: bare=N system=N
- django/contrib/postgres/fields/jsonb.py [CWE-89, 15 fns, 0 SAST cands]: bare=N system=N
- tests/postgres_tests/test_hstore.py [CWE-89, 40 fns, 0 SAST cands]: bare=N system=N
- django/contrib/admin/views/decorators.py [CWE-79, 5 fns, 0 SAST cands]: bare=Y system=Y