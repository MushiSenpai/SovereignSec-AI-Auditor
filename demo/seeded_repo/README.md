# Seeded vulnerable demo repo

> ⚠️ **INTENTIONALLY VULNERABLE. DO NOT DEPLOY.** This is a test fixture for the
> SovereignSec-AI auditor — analogous to DVWA / OWASP Juice Shop, used only to
> acceptance-test the L1–L5 layers and as the M5 split-screen demo target.

## What's planted (ground truth in [`GROUND_TRUTH.json`](GROUND_TRUTH.json))
| ID | Vuln | Where | Why it's the right test |
|---|---|---|---|
| 1 | **CWE-89 SQL injection** | `db.find_user` via `app.user → services.user_lookup → db.find_user` | exercises **cross-file** taint (L1 call graph + L2 graph-walk); Semgrep CE alone can't follow it |
| 2 | **CWE-79 reflected XSS** | `app.greet` | in-file taint; should be caught by SAST + agent |
| FP | parameterized query (**must NOT be reported**) | `db.find_user_safe` via `app.safe_user` | tests **false-positive suppression** (L4) — a naive matcher flags every `cursor.execute()` |

## Run
```bash
pip install -r requirements.txt
python app.py                 # serves on :5001  (DO NOT expose)
pytest tests/                 # functional suite — the L5 regression gate
python exploits/check_sqli.py # dynamic oracle: exit 0 == exploit landed (vulnerable)
```

## How L5 uses it (IMPL_SPEC §5)
`exploit_pre == SUCCESS` (before patch) **and** `exploit_post == FAILURE` (after the
auditor's patch) **and** `pytest` still green **and** differential/golden tests pass —
unanimous across N=5 runs — else the patch is rejected as overfit/broken.

## Acceptance checklist this fixture backs
- **L1:** the call graph links `app.user → services.user_lookup → db.find_user` across 3 files.
- **L2:** retrieval for the `cur.execute` sink surfaces the `request.args.get` source.
- **L3:** our Semgrep rules + Bandit fire on findings 1 & 2; not on the FP path.
- **L4:** agent triages candidates, **drops the `find_user_safe` FP**, writes a patch.
- **L5:** the SQLi patch flips the exploit and keeps `pytest` green.

## TODO for full Tier-D parity (IMPL_SPEC §5)
- Add an explicit `impossible`/secure variant module + `tests/golden.jsonl` (differential).
- Add a digest-pinned `Dockerfile` with deterministic `SOURCE_DATE_EPOCH` for the N-run container harness.
- Add one seeded app per OWASP Top 10:2025 class (this one covers Injection + XSS).
