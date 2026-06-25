# SovereignSec-AI — haystack localization (bare vs one-shot vs agentic vs HYBRID)

Label: **v2cov**. Localize the vuln in a full file (~11 functions each, 29 files; 5×CWE-22, 5×CWE-502, 5×CWE-78, 5×CWE-79, 5×CWE-89, 4×CWE-918). Auditor = 32B; LLM-judge scores localization vs ground truth.

| config | recall | finding precision |
|---|---|---|
| BARE (file only) | 0.90 | — |
| ONE-SHOT (+ SAST hints) | 0.76 | — |
| AGENTIC (trace→triage→validate) | 0.69 | 0.61 (23/38) |
| **HYBRID (LLM breadth ∪ system-confirmed)** | **0.97** | 0.51 (27/53) |

**bare 0.90 · one-shot 0.76 · agentic 0.69 · hybrid 0.97.** Of the hybrid's findings, **38** carry deterministic system proof (taint path / SAST) — the high-confidence subset an analyst triages first.

Per-file (bare / one-shot / agentic / hybrid):
- app/m1_ecommerce.py [CWE-89, 11 fns]: Y / Y / Y / Y
- app/m2_blog.py [CWE-89, 10 fns]: Y / Y / Y / Y
- app/m3_admin.py [CWE-89, 12 fns]: Y / Y / Y / Y
- app/m4_rest_api.py [CWE-89, 13 fns]: Y / Y / Y / Y
- app/m5_internal_tool.py [CWE-89, 12 fns]: Y / Y / Y / Y
- app/m1_shop_search.py [CWE-79, 10 fns]: Y / Y / Y / Y
- app/m2_blog_comments.py [CWE-79, 11 fns]: Y / N / Y / Y
- app/m3_admin_users.py [CWE-79, 10 fns]: Y / Y / Y / Y
- app/m4_status_dashboard.py [CWE-79, 12 fns]: Y / Y / N / Y
- app/m5_api_profile.py [CWE-79, 12 fns]: Y / Y / N / Y
- app/module1_ecommerce.py [CWE-78, 12 fns]: Y / Y / Y / Y
- app/module2_blog.py [CWE-78, 11 fns]: Y / N / Y / Y
- app/module3_admin.py [CWE-78, 9 fns]: Y / N / Y / Y
- app/module4_restapi.py [CWE-78, 12 fns]: Y / N / Y / Y
- app/module5_internal.py [CWE-78, 11 fns]: Y / Y / Y / Y
- app/m1_blog_media.py [CWE-22, 10 fns]: Y / Y / N / Y
- app/m2_ecommerce_invoices.py [CWE-22, 10 fns]: Y / Y / Y / Y
- app/m3_admin_logs.py [CWE-22, 10 fns]: Y / Y / Y / Y
- app/m4_rest_api_reports.py [CWE-22, 12 fns]: N / Y / N / Y
- app/m5_internal_fileshare.py [CWE-22, 12 fns]: N / Y / N / N
- app/module1_easy_blog.py [CWE-918, 12 fns]: Y / Y / Y / Y
- app/module2_medium_ecommerce.py [CWE-918, 12 fns]: N / N / Y / Y
- app/module3_medium_admin.py [CWE-918, 12 fns]: Y / N / Y / Y
- app/module4_hard_restapi.py [CWE-918, 15 fns]: Y / N / Y / Y
- app/cart_views.py [CWE-502, 11 fns]: Y / Y / N / Y
- app/import_views.py [CWE-502, 12 fns]: Y / Y / N / Y
- app/preferences.py [CWE-502, 11 fns]: Y / Y / N / Y
- app/webhooks.py [CWE-502, 12 fns]: Y / Y / N / Y
- app/report_jobs.py [CWE-502, 13 fns]: Y / Y / Y / Y