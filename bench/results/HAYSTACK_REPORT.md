# SovereignSec-AI — haystack localization (does the SYSTEM help the LLM?)

Task: localize the vuln in a full pre-fix file (~14 functions each, 9 files, 10 SQLi + 5 XSS). Auditor = 32B; LLM-judge scores localization vs ground truth.

| config | localization accuracy |
|---|---|
| BARE (file only) | 0.67 |
| SYSTEM (+ SAST candidates) | 1.00 |

**System delta: 0.67 -> 1.00 (+0.33).**

Per-file:
-  app/views_0.py [CWE-89, 11 fns, 2 SAST cands]: bare=Y system=Y
-  app/views_1.py [CWE-89, 11 fns, 2 SAST cands]: bare=Y system=Y
-  app/views_2.py [CWE-89, 11 fns, 2 SAST cands]: bare=Y system=Y
-  app/views_3.py [CWE-79, 11 fns, 1 SAST cands]: bare=N system=Y
-  app/views_4.py [CWE-79, 11 fns, 1 SAST cands]: bare=N system=Y
-  app/views_5.py [CWE-79, 11 fns, 1 SAST cands]: bare=N system=Y
-  app/views_6.py [CWE-78, 11 fns, 1 SAST cands]: bare=Y system=Y
-  app/views_7.py [CWE-78, 11 fns, 1 SAST cands]: bare=Y system=Y
-  app/views_8.py [CWE-78, 11 fns, 1 SAST cands]: bare=Y system=Y