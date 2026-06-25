# SovereignSec-AI — Phase 1 Implementation Spec (grounded reference)

> **Provenance:** `sscai-phase1-grounding` workflow (run `wf_27a528da-613`), **re-run completed 2026-06-24 — ALL 15 agents succeeded** (the earlier session-limit failures are resolved; data-mining + every verify pass now ran). Each of the 7 components was researched then **adversarially verified against primary sources** (all verdicts `partially_confirmed` = confirmed-with-corrections, the healthy outcome). Verification corrections are folded in and **OVERRIDE** the drafts.
>
> **How to read this:** anything marked `RUNTIME-CHECK` / `[RUNTIME CHECK]` must be smoke-tested on the actual 5090 — the field moves; this is a strong starting point, not gospel. Per-component sources + corrections are in the appendix.
>
> *This file supersedes the earlier draft (which had an authored-not-verified data-mining section). Component 1 below is now workflow-verified.*

---
I have all six verified component specs. I'll synthesize them directly into the consolidated specification, applying every verification correction as an override.

# SovereignSec-AI — Phase 1 Implementation-Ready Technical Specification

*All six components below fold in the verification corrections (which override the drafts). Anything the verification marked unverifiable or low-confidence is flagged inline as `RUNTIME-CHECK` so it gets validated empirically rather than trusted. Today: June 2026.*

---

## Component 1 — Data-Mining (vuln→patch pair corpus)

**Final approach.** Two complementary CC-BY-4.0 sources joined on fix-commit SHA. **Source A** = GitHub Advisory Database (fresh, framework-targeted). **Source B** = CVEfixes pre-mined **SQLite** (volume, ready-parsed method bodies). MoreFixes is an *optional* extra source but is **PostgreSQL, not SQLite** (correction below).

### Source A — GitHub Advisory Database (OSV JSON)
One-time online fetch, mine offline forever after:
```bash
git clone --depth 1 https://github.com/github/advisory-database.git   # JSON only → shallow OK
```
Layout (verified): `advisories/github-reviewed/<YYYY>/<MM>/<GHSA-id>/<GHSA-id>.json` (+ `unreviewed/...`). One OSV JSON per GHSA. Prefer `github-reviewed`.

**Filter:** keep advisories where any `affected[].package.ecosystem == "PyPI"` and normalized `affected[].package.name` ∈ framework set.

**CRITICAL GOTCHA (verified on real CVE-2024-56374 / GHSA-qcgg-j2x8-h9g8):** GHSA tags fix-commit links as `references[].type == "WEB"`, **not** `"FIX"`. All 4 Django fix commits in that advisory are `WEB`. Harvest commit URLs from **both** FIX and WEB references with:
```
https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}
```
Use `aliases[]` (CVE-*, PYSEC-*) as the join key to Source B. CWE from `database_specific.cwe_ids[]`. Ranges: `affected[].ranges[].type` ∈ `{ECOSYSTEM,SEMVER,GIT}`, events `introduced`/`fixed` (no leading `v`; GIT ranges use 40-hex hashes that need the cloned commit graph to resolve).

**OSV field paths:** `id`, `aliases[]`, `affected[].package.{ecosystem,name}`, `affected[].ranges[].events[].{introduced,fixed}`, `references[].{type,url}`, `database_specific.cwe_ids[]`.

### Source B — CVEfixes SQLite (offline)
```bash
# one-time: download Zenodo dump, DOI 10.5281/zenodo.4476563  → CVEfixes.db
# (regenerating from scratch needs NVD API key + GitHub token + live net — ONLY online step; avoid)
```
Schema (verified exact): `cve(cve_id, published_date, …)`, `fixes(cve_id, hash, repo_url)`, `repository(repo_url, repo_name, …)`, `commits(hash, repo_url, author, committer_date, msg, parents, num_lines_added/deleted, dmm_*)`, `file_change(file_change_id, hash, filename, old_path, new_path, change_type, diff, diff_parsed, code_after, code_before, nloc, complexity, token_count, programming_language)`, `method_change(method_change_id, file_change_id, name, signature, parameters, start_line, end_line, code, nloc, complexity, token_count, top_nesting_level, before_change)`.

**Pairing:** for one `file_change_id`, `before_change=TRUE` row = vulnerable body, `before_change=FALSE` = patched; pair on `(filename, name, signature)`. Filter `file_change.programming_language='Python'`.

### Corrections applied (override draft)
- **MoreFixes is PostgreSQL, NOT SQLite.** It ships as `postgrescvedumper.sql.zip` (~3.5GB → ~16GB Postgres DB, Zenodo record 13983082). `sqlite3.connect('CVEfixes.db')` works for CVEfixes only. To use MoreFixes offline: load into local PostgreSQL and query via `psycopg`/`psycopg2` (still zero-egress once loaded), or convert PG→SQLite. **Net rule: CVEfixes=SQLite, MoreFixes=PostgreSQL.**
- **MoreFixes volume:** ~**29,203 CVEs / 35,276 fix commits / 39,931 patch files** (not "~26k+"). It is "based on CVEfixes" (enhanced repo discovery via modified Prospector), not a drop-in successor.
- **Shallow-clone hazard for Source A reconstruction:** PyDriller computes diffs against the commit's **parent**. The framework repos (django/django, pallets/flask…) you clone for `Repository(path, single=<sha>)` mining **MUST be full-depth** (or `git fetch --unshallow`). A `--depth 1` clone of a framework repo yields empty/incorrect pairs. (The advisory-database repo itself is fine shallow — JSON only.)
- **Base-model id (project-wide):** the HF repo is `mistralai/Devstral-Small-2-24B-Instruct-2512` (date-suffixed), Apache-2.0, 24B dense, FP8 — use the exact `-2512` id everywhere.
- **`before_change` portability:** SQLite stores it as text `'True'`/`'False'`; normalize case-insensitively. On MoreFixes-Postgres it comes back as a **native bool** — compare with the driver bool, not string-match.

### Label hygiene (PrimeVul / ReposVul)
- **Untangle tangled commits:** drop `tests?/docs?/examples?/changelog/.github` paths; keep only methods PyDriller flags in `changed_methods`; for multi-commit fixes diff each commit vs its own parent (`single=sha`); optional local-Devstral pass to confirm each hunk is security-relevant.
- **Dedup** vulnerable+patched bodies by normalized-source hash (strip comments/whitespace) **across all splits**, not per-split.
- **Chronological split** by `commits.committer_date` / `cve.published_date` (e.g. train < 2024-01-01, test ≥). **Never random** (random leaks future fixes — core PrimeVul finding).
- Track provenance per pair: GHSA id, CVE, commit SHA, repo_url, CWE, source+DOI (CC-BY-4.0 attribution + license-gating before redistributing bodies).

### Code sketch (key functions)
```python
import os, re, json, glob, hashlib, sqlite3
from pathlib import Path
from pydriller import Repository  # wraps GitPython + lizard

FRAMEWORKS = {"django","flask","fastapi","djangorestframework","starlette","werkzeug","jinja2"}  # RUNTIME-CHECK: design choice, tune coverage
COMMIT_RE  = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
SKIP_PATH  = re.compile(r"(^|/)(tests?|docs?|examples?|changelog|\.github)/", re.I)
def norm(n): return n.lower().replace("_","-")

def iter_pypi_fix_commits(db_root):
    pat = os.path.join(db_root,"advisories","github-reviewed","*","*","GHSA-*","GHSA-*.json")
    for fp in glob.glob(pat):
        adv = json.loads(Path(fp).read_text())
        pkgs = {norm(a["package"]["name"]) for a in adv.get("affected",[])
                if a.get("package",{}).get("ecosystem")=="PyPI"}
        if not (pkgs & FRAMEWORKS): continue
        urls = [r["url"] for r in adv.get("references",[]) if r.get("type") in ("FIX","WEB")]  # BOTH
        seen=set()
        for u in urls:
            m = COMMIT_RE.search(u)
            if not m: continue
            org,repo,sha = m.groups()
            if (org,repo,sha) in seen: continue
            seen.add((org,repo,sha))
            yield {"ghsa":adv["id"],
                   "cve":next((x for x in adv.get("aliases",[]) if x.startswith("CVE-")),None),
                   "cwe":adv.get("database_specific",{}).get("cwe_ids",[]),
                   "repo_url":f"https://github.com/{org}/{repo}.git","sha":sha,
                   "pkgs":sorted(pkgs & FRAMEWORKS)}

def extract_pairs_from_commit(local_repo_path, sha, meta):  # repo MUST be full-depth
    pairs=[]
    for c in Repository(local_repo_path, single=sha,
                        only_modifications_with_file_types=['.py']).traverse_commits():
        for f in c.modified_files:
            path=f.new_path or f.old_path or ""
            if not path.endswith(".py") or SKIP_PATH.search(path): continue
            before={(m.name,m.long_name):m for m in f.methods_before}
            for m_a in f.changed_methods:
                m_b=before.get((m_a.name,m_a.long_name))
                if not m_b or not f.source_code_before or not f.source_code: continue
                vuln    ="\n".join(f.source_code_before.split("\n")[m_b.start_line-1:m_b.end_line])
                patched ="\n".join(f.source_code.split("\n")[m_a.start_line-1:m_a.end_line])
                if vuln.strip()==patched.strip(): continue
                pairs.append({**meta,"file":path,"func":m_a.name,"vuln_code":vuln,
                              "patched_code":patched,"commit_date":c.committer_date.isoformat()})
    return pairs

def cvefixes_python_pairs(db="CVEfixes.db"):
    con=sqlite3.connect(db); con.row_factory=sqlite3.Row
    rows=con.execute("""
        SELECT c.cve_id, x.repo_url, f.filename, m.name, m.signature, m.code,
               m.before_change, cm.committer_date
        FROM method_change m
        JOIN file_change f ON m.file_change_id=f.file_change_id
        JOIN commits cm ON f.hash=cm.hash
        JOIN fixes x ON f.hash=x.hash
        JOIN cve c ON x.cve_id=c.cve_id
        WHERE f.programming_language='Python'""").fetchall()
    bucket={}
    for r in rows:
        k=(r["filename"],r["name"],r["signature"])
        is_before=str(r["before_change"]).lower() in ("true","before","1")  # case-insensitive
        bucket.setdefault(k,{})["vuln" if is_before else "patched"]=dict(r)
    out=[]
    for k,v in bucket.items():
        if "vuln" in v and "patched" in v and v["vuln"]["code"].strip()!=v["patched"]["code"].strip():
            out.append({"cve":v["vuln"]["cve_id"],"repo_url":v["vuln"]["repo_url"],
                        "file":k[0],"func":k[1],"vuln_code":v["vuln"]["code"],
                        "patched_code":v["patched"]["code"],"commit_date":v["vuln"]["committer_date"]})
    con.close(); return out

def norm_hash(code):
    s=re.sub(r"#.*","",code); s=re.sub(r"\s+"," ",s).strip()
    return hashlib.sha256(s.encode()).hexdigest()

def dedup_and_split(pairs, cutoff="2024-01-01"):
    seen,uniq=set(),[]
    for p in pairs:
        h=(norm_hash(p["vuln_code"]),norm_hash(p["patched_code"]))
        if h in seen: continue
        seen.add(h); uniq.append(p)
    uniq.sort(key=lambda p:p["commit_date"])
    return ([p for p in uniq if p["commit_date"]<cutoff],
            [p for p in uniq if p["commit_date"]>=cutoff])
```

### Data formats
- **OSV JSON** (per GHSA): fields above.
- **CVEfixes SQLite:** schema above; `before_change` is text `'True'/'False'`.
- **Mined pair record:** `{ghsa?,cve,cwe[],repo_url,sha?,file,func,vuln_code,patched_code,commit_date,source,doi}`.

### Libraries
| lib | version | license | purpose |
|---|---|---|---|
| pydriller | ≥2.6 | Apache-2.0 | offline fix-commit mining, `changed_methods`, source before/after |
| GitPython | ≥3.1 | BSD-3 | raw git (pulled in by PyDriller) |
| sqlite3 | stdlib | Python-2.0 | CVEfixes queries |
| lizard | ≥1.17 | MIT | method boundaries/complexity (used by PyDriller) |
| psycopg | ≥3.1 | LGPL-3.0 | **only if** using MoreFixes/Postgres |

### Gotchas
FIX-vs-WEB (scan both); multi-commit fixes (diff each vs parent); tangled commits; `before_change` is a version-varying string; `programming_language` is **content-guessed** not extension-based (cross-check `.py`); never random-split; regenerating CVEfixes is the only online step (prefer Zenodo dump); GIT ranges need the clone; CC-BY-4.0 attribution + per-repo license gating.

### `RUNTIME-CHECK` / low-confidence
- Framework-set membership is a design choice; coverage varies per package — tune empirically.
- `Code/create_CVEfixes_from_scratch.sh` exact filename unconfirmed (NVD-key+token requirement *is* confirmed) — verify before relying on it.
- `before_change` literal convention across **all** Zenodo dump versions unconfirmed — the case-insensitive normalizer is the defensive cover.

---

## Component 2 — repo-graph-L1 (offline call/import graph + symbol table + lightweight taint)

**Final approach: HYBRID, two-tier.** Tree-sitter = error-tolerant **syntax** layer (enumeration, decorators/routes, call-site extraction, slicing substrate). Jedi = **semantic** layer, fully offline (goto-definition, find-references, import resolution, attribute/type inference). Build the call graph + symbol table yourself as a **NetworkX `MultiDiGraph`** (nodes = FQNs), populated by walking tree-sitter call nodes and resolving callees via `jedi.Script(...).goto(follow_imports=True)`. Taint = **summary-based 2-level engine** (intraprocedural def-use seeded from SOURCES → propagate to SINKS; interprocedural worklist over the call graph, bounded depth ~5, param→return / param→sink summaries). **Do not** build on tree-sitter alone (no name binding/imports/types), and **do not** depend on PyCG/Scalpel/PyT/Pysa/CodeQL as the engine.

### Install (PINNED — corrected versions)
```bash
pip install tree-sitter==0.25.2 tree-sitter-python==0.25.0 jedi networkx
# tree-sitter-python has NO 0.25.2 — latest is 0.25.0. Pinning 0.25.2 FAILS. (leave unpinned or use 0.25.0)
```
Prebuilt manylinux wheels (no C compiler). Jedi 0.20.0 (MIT, 2026-05-01). All offline once cached.

### Current tree-sitter API (0.23+ / mandatory in 0.25 — empirically verified)
- `Language(tspython.language())` (capsule). `Parser(PY)` takes the Language **in the constructor**. `parser.set_language()` and `Language(path,'python')` are **REMOVED**.
- `captures()`/`matches()` moved **off `Query` onto `QueryCursor`**: `QueryCursor(query).captures(node)` → `dict[str, list[Node]]`; `.matches(node)` → `list[(pattern_index:int, dict[str,list[Node]])]`.
- `node.text` (bytes), `.type`, `.start_point`/`.end_point` = `(row,col)` **0-based**, `.children`, `.child_by_field_name(name)`.

### Jedi API (empirically verified; kwargs are keyword-only after `*`)
- `jedi.Project(path, *, environment_path=None, sys_path=None, …)` — set env to local interpreter for offline.
- `jedi.Script(code=src, *, path=file, project=proj).goto(line, column, *, follow_imports=True)` → `list[Name]`. **Jedi line numbers are 1-based** → pass `tree_sitter_row + 1`.
- `Name`: `.full_name` (FQN), `.module_path`, `.line`, `.column`, `.type`, `.description`.
- `.get_references(line, col, scope='project')`, `.get_names(all_scopes=True, definitions=True, references=False)`.

### Code sketch
```python
import pathlib, networkx as nx
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Query, QueryCursor
import jedi

PY=Language(tspython.language()); PARSER=Parser(PY)
CALL_Q=Query(PY,"(call function: [(identifier) @fn (attribute attribute:(identifier) @fn)])")

SOURCES={"request.GET","request.POST","request.args","request.form","request.json",
         "request.data","request.query_params","os.environ","sys.argv","input"}
SINKS={"execute","executemany","system","popen","eval","exec","run","call",
       "check_output","render_template_string","loads","Popen"}  # RUNTIME-CHECK: team's own set, test it

class RepoGraph:
    def __init__(self, repo):
        self.repo=pathlib.Path(repo)
        self.proj=jedi.Project(str(self.repo))   # offline: resolves against local analysis venv
        self.g=nx.MultiDiGraph(); self.symbols={}
    def build(self):
        for f in self.repo.rglob("*.py"):
            src=f.read_bytes(); tree=PARSER.parse(src)
            self._index_defs(f,src); self._index_calls(f,src,tree)
    def _index_defs(self,f,src):
        s=jedi.Script(code=src.decode("utf8","replace"),path=str(f),project=self.proj)
        for n in s.get_names(all_scopes=True,definitions=True,references=False):
            if n.type in ("function","class","module"):
                fqn=n.full_name or f"{f.stem}.{n.name}"
                self.symbols[fqn]={"file":str(f),"line":n.line,"type":n.type}
                self.g.add_node(fqn,**self.symbols[fqn])
    def _index_calls(self,f,src,tree):
        caps=QueryCursor(CALL_Q).captures(tree.root_node)   # dict[str,list[Node]]
        s=jedi.Script(code=src.decode("utf8","replace"),path=str(f),project=self.proj)
        for node in caps.get("fn",[]):
            row,col=node.start_point
            try: targets=s.goto(row+1,col,follow_imports=True)   # +1: TS 0-based → jedi 1-based
            except Exception: targets=[]
            caller=self._enclosing_fqn(f,node)
            for t in targets:
                self.g.add_edge(caller, t.full_name or t.name, kind="calls",
                                site_line=row+1, callee_file=str(t.module_path))
    def _enclosing_fqn(self,f,node):
        n=node
        while n is not None and n.type not in ("function_definition","module"): n=n.parent
        if n is None or n.type=="module": return f"{f.stem}.<module>"
        nm=n.child_by_field_name("name")
        return f"{f.stem}.{nm.text.decode()}" if nm else f"{f.stem}.<anon>"
    def taint_summaries(self):
        # 1) intraprocedural: per-function def-use, seed assignments from SOURCES, propagate
        #    through =, f-strings, +, .format, %; record (func→sink) & (func,param_idx→sink) summaries.
        # 2) interprocedural worklist over 'calls' edges, bounded depth ~5; emit
        #    {source, sink, path:[FQN...], confidence:'heuristic'}.  Best-effort; L4/L5 adjudicate.
        ...
```

### Corrections applied (override draft)
- **code2flow is MIT, NOT GPL-3.0.** Delete the entire licensing-disqualification argument. (You may still reject it technically as a heuristic AST-name resolver, like pyan3.)
- **`tree-sitter-python` has no 0.25.2** — use `0.25.0` or leave unpinned (core `tree-sitter==0.25.2` is fine).
- **Scalpel IS on PyPI** as `python-scalpel==1.0b0` (2022-12-25, stale) — not "absent." Avoid as a hard dep on maintenance grounds. (Bare `scalpel` is an unrelated dead 2010 audio editor — do not install it.)
- **`tree-sitter-language-pack` requires `tree-sitter>=0.23`** (not "0.21–0.26"); 1.10.7, MIT, 306 langs, abi3 wheels. Optional — Python-only auditor should use the single `tree-sitter-python` wheel.
- **PyCG** phrasing: `python_requires>=3.4` (runs on 3.4+) but syntax support is frozen at an old era (breaks on match/walrus/type-alias); archived 2023-11-26.

### Libraries
| lib | version | license | role |
|---|---|---|---|
| tree-sitter | ==0.25.2 | MIT | syntax layer |
| tree-sitter-python | ==0.25.0 | MIT | Python grammar |
| jedi | 0.20.0 | MIT | semantic resolution |
| networkx | latest | BSD-3 | graph store |

Rejected: PyCG (Apache-2.0, archived), Scalpel/`python-scalpel` (Apache-2.0, 1.0b0 stale), code2flow (**MIT** — rejected on technical grounds only), pyan3 (heuristic), PyT (abandoned), Pysa+Pyre / CodeQL (heavy / not pure-pip).

### Gotchas
Breaking 0.23 API (Language capsule + Parser-in-ctor; `set_language` gone); breaking 0.25 (`QueryCursor` for captures/matches); tree-sitter is syntax-only; `tree-sitter-languages` (grantjenks) unmaintained; **Jedi offline caveat — accuracy depends on the target repo's deps being installed in the analysis venv, so pre-install/vendor `requirements.txt` into the auditor venv**; Jedi 1-based vs TS 0-based (`row+1`); static taint is necessarily approximate (getattr/`**kwargs`/monkeypatch/ORM lazy eval defeat it — emit confidence levels, let L4+L5 adjudicate); don't dump whole files to the model — use the L1 graph to extract minimal source→sink slices as the retrieval index.

### `RUNTIME-CHECK` / low-confidence
- SOURCES/SINKS sets and the worklist algorithm are the team's own design — test against fixtures.
- PyCG 99.2%/69.9% precision/recall not re-verified (non-load-bearing; PyCG rejected anyway).
- `tree-sitter-language-pack` "ABI-14" label unconfirmed (abi3 confirmed; non-load-bearing).

---

## Component 3 — sast-rules-L3 (deterministic candidate-finder)

**Final approach.** Semgrep OSS/CE as the deterministic candidate-finder, run **fully air-gapped** with `--config` → **local** rules dir, + **Bandit** as a complementary Python-only AST SAST. Both emit JSON parsed into a normalized `Finding`. **Strongly evaluate Opengrep** (correction below) — it restores cross-file taint *for free* under LGPL-2.1.

### Licensing (confirmed)
- **Engine (Semgrep CE):** LGPL-2.1. You invoke the CLI as a subprocess → no copyleft reach into your code. **OK to use.**
- **Semgrep-maintained registry rules** (`p/python`, `r/...`, the "community" rules): **"Semgrep Rules License v.1.0"** — internal-use-only, **no redistribution / no competing product. Do NOT bundle them.** Ship only rules you wrote (you own them) or third-party OSS rule packs under their own license.
- **Pro/cloud (proprietary, not offline):** cross-file/cross-function taint, the 20k+ Pro rules, AI triage, SCA, Secrets.

### CRITICAL constraint
**OSS taint is intra-procedural / single-file ONLY.** `pattern-propagators` work in OSS but only within one function. Cross-file proof is **L4's** job (your graph + LLM agent) — *unless* you adopt Opengrep.

### Offline guarantee
Local `--config` path ⇒ no rule fetch. Kill **both** residual network paths: `--metrics=off` **AND** `SEMGREP_ENABLE_VERSION_CHECK=0` (env, needs Semgrep ≥1.61.1) and/or `--disable-version-check`. A bare registry shorthand in `--config` silently fetches → fails/hangs air-gapped. Belt-and-suspenders: run in a no-egress sandbox.

### Canonical invocations
```bash
SEMGREP_ENABLE_VERSION_CHECK=0 semgrep scan \
  --config /opt/sovereignsec/rules/ \
  --json --metrics=off --disable-version-check --no-git-ignore \
  --timeout 60 --output /tmp/semgrep.json /path/to/target

bandit -r /path/to/target -f json -o /tmp/bandit.json -ll   # -ll = MEDIUM+; add -ii for confidence
semgrep --validate --config /opt/sovereignsec/rules/        # lint rules
semgrep --test     --config /opt/sovereignsec/rules/        # unit-test via # ruleid:/# ok:
```

### JSON fields
- **Semgrep:** top `{results,errors,paths,version}`; per-result `check_id, path, start.{line,col}, end.{line,col}, extra.{message,severity(ERROR|WARNING|INFO),lines,metadata.{cwe[],owasp[],references,category,confidence},fingerprint}`; **taint rules add `extra.dataflow_trace.{taint_source,intermediate_vars,taint_sink}`**.
- **Bandit:** top `{results,errors,metrics,generated_at}`; per-result `test_id(e.g. B602), test_name, issue_severity(LOW|MEDIUM|HIGH), issue_confidence, issue_cwe:{id(int),link}, issue_text, filename, line_number, line_range[], col_offset, code`.

### Corrections applied (override draft)
- **`semgrep scan` exit code is NOT 1-on-findings.** `semgrep scan` exits **0 even with findings**; add `--error` if you want returncode to signal findings (1-on-findings is the default only for `semgrep ci` / the deprecated bare `semgrep`). **Rely on parsing `results[]`, not the return code.** Exit ≥2 = real error.
- **SQLi rule literal-exclusion bug:** `metavariable-pattern` on `$Q` matching a string literal **requires `language: generic` inside the `metavariable-pattern`**, else `pattern-not: "..."` is ineffective / may error on `--validate`. Prefer a *positive* "looks like f-string/concat/%-format" check over a fragile `pattern-not` on a literal. (Known taint-vs-literal limitation: GH semgrep#10776.)
- **SSRF positional-arg bug:** `requests.request(..., $URL, ...)` is fragile (url is the 2nd positional). Use `requests.request($METHOD, $URL, ...)` **and** `requests.request(..., url=$URL, ...)`.
- **Version pins:** Bandit current is **1.9.3** (Jan 2026) — pin that, not "1.8.x". Semgrep latest ~**1.167.0** (2026-06-17, ~weekly) — pin an **exact** version for reproducible air-gap, not `1.*`. Re-run `--validate` + re-test the JSON parser on every bump.
- **MAJOR — evaluate Opengrep.** `github.com/opengrep/opengrep` (Jan-2025 LGPL-2.1 fork of Semgrep CE, backed by 10+ AppSec vendors) **restores cross-function / interfile taint + fingerprinting for free**, same rule format + JSON/SARIF, drop-in. For a sovereign air-gapped project this means you may not need to punt all cross-file taint to L4. **Benchmark Opengrep vs Semgrep CE for L3.** (Rule-licensing trap still applies — write your own rules regardless.)
- **Minor:** `--metrics` default is `auto` (sends only when `--config` pulls from the server or you're logged in); explicit `--metrics=off` is still correct defense-in-depth. Output consistency — pick `--output` *or* stdout, not both. Dedupe is brittle: normalize CWE to bare `CWE-<n>` (extract numeric id from Semgrep's long string), dedupe on `(cwe_id, file)` with a small line-window, not exact line.

### Rule set (4 runnable rules — corrected)
Ship these (or equivalents) under your own license; validate before every run.
```yaml
rules:
  # 1) SQL INJECTION (CWE-89) — taint; note language:generic fix in metavariable-pattern
  - id: ssec-python-sql-injection-taint
    mode: taint
    message: Tainted user input reaches a raw SQL sink without parameterization.
    languages: [python]
    severity: ERROR
    metadata: {cwe: ["CWE-89: SQL Injection"], owasp: ["A03:2021 - Injection"], category: security, confidence: HIGH}
    pattern-sources:
      - patterns: [{pattern-either: [
          {pattern: request.GET.get(...)}, {pattern: request.POST.get(...)},
          {pattern: request.GET[...]}, {pattern: request.POST[...]},
          {pattern: request.args.get(...)}, {pattern: request.form.get(...)},
          {pattern: request.values.get(...)}, {pattern: request.query_params.get(...)}]}]
    pattern-sanitizers: [{pattern: int(...)}]
    pattern-sinks:
      - patterns:
          - pattern-either: [
              {pattern: $CUR.execute($Q, ...)}, {pattern: $CUR.executemany($Q, ...)},
              {pattern: $MODEL.objects.raw($Q, ...)}, {pattern: $QS.extra(...)}]
          - metavariable-pattern:
              metavariable: $Q
              language: generic            # REQUIRED so the literal-exclusion below works
              patterns: [{pattern-not: "..."}]   # better: positive f-string/concat/% check
  # 2) SSRF (CWE-918) — taint; fixed positional/named url binding
  - id: ssec-python-ssrf-taint
    mode: taint
    message: User-controlled value reaches an outbound HTTP request URL (SSRF).
    languages: [python]
    severity: ERROR
    metadata: {cwe: ["CWE-918: SSRF"], owasp: ["A10:2021 - SSRF"], category: security, confidence: MEDIUM}
    pattern-sources:
      - pattern-either: [
          {pattern: request.GET.get(...)}, {pattern: request.POST.get(...)},
          {pattern: request.args.get(...)}, {pattern: request.query_params.get(...)},
          {pattern: request.json[...]}]
    pattern-sanitizers: [{patterns: [{pattern-either: [{pattern: validate_url(...)},{pattern: is_allowed_host(...)}]}]}]
    pattern-sinks:
      - pattern-either: [
          {pattern: requests.get($URL, ...)}, {pattern: requests.post($URL, ...)},
          {pattern: requests.request($METHOD, $URL, ...)}, {pattern: requests.request(..., url=$URL, ...)},
          {pattern: urllib.request.urlopen($URL, ...)}, {pattern: httpx.get($URL, ...)}]
  # 3) COMMAND INJECTION (CWE-78) — search; flag dangerous shape, exclude constants
  - id: ssec-python-command-injection
    mode: search
    message: OS command via shell from a non-constant value.
    languages: [python]
    severity: ERROR
    metadata: {cwe: ["CWE-78: OS Command Injection"], owasp: ["A03:2021 - Injection"], category: security, confidence: HIGH}
    patterns:
      - pattern-either:
          - patterns: [{pattern-either: [{pattern: os.system($CMD)},{pattern: os.popen($CMD, ...)}]}, {pattern-not: os.system("...")}]
          - patterns: [{pattern-either: [
              {pattern: subprocess.run(..., shell=True, ...)}, {pattern: subprocess.call(..., shell=True, ...)},
              {pattern: subprocess.Popen(..., shell=True, ...)}, {pattern: subprocess.check_output(..., shell=True, ...)}]},
              {pattern-not: subprocess.run("...", shell=True, ...)}]
  # 4) INSECURE DESERIALIZATION (CWE-502) — search
  - id: ssec-python-insecure-deserialization
    mode: search
    message: Untrusted deserialization (pickle / unsafe yaml.load) enables RCE.
    languages: [python]
    severity: ERROR
    metadata: {cwe: ["CWE-502: Deserialization of Untrusted Data"], owasp: ["A08:2021"], category: security, confidence: HIGH}
    patterns:
      - pattern-either: [
          {pattern: pickle.loads(...)}, {pattern: pickle.load(...)}, {pattern: cPickle.loads(...)},
          {patterns: [{pattern: yaml.load($X)}, {pattern-not: yaml.load($X, Loader=yaml.SafeLoader)}, {pattern-not: yaml.load($X, Loader=yaml.CSafeLoader)}]},
          {pattern: yaml.unsafe_load(...)}]
```

### Orchestrator (normalized Finding)
```python
import json, subprocess, os
from dataclasses import dataclass, asdict
@dataclass
class Finding:
    tool:str; rule_id:str; cwe:str|None; severity:str; confidence:str|None
    file:str; line:int; end_line:int|None; message:str; code:str|None; raw:dict
_SG={"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}

def run_semgrep(rules_dir, target):
    env={**os.environ,"SEMGREP_ENABLE_VERSION_CHECK":"0"}
    cmd=["semgrep","scan","--config",rules_dir,"--json","--metrics=off",
         "--disable-version-check","--no-git-ignore","--timeout","60",target]
    p=subprocess.run(cmd,capture_output=True,text=True,env=env,check=False)  # parse JSON, ignore rc
    out=[]
    for r in json.loads(p.stdout).get("results",[]):
        md=r.get("extra",{}).get("metadata",{}); cwe=(md.get("cwe") or [None])[0]
        out.append(Finding("semgrep",r["check_id"],cwe,_SG.get(r["extra"].get("severity","INFO"),"LOW"),
                           md.get("confidence"),r["path"],r["start"]["line"],r.get("end",{}).get("line"),
                           r["extra"].get("message",""),r["extra"].get("lines"),r))
    return out

def run_bandit(target):
    p=subprocess.run(["bandit","-r",target,"-f","json","-ll"],capture_output=True,text=True,check=False)
    out=[]
    for r in json.loads(p.stdout).get("results",[]):
        out.append(Finding("bandit",r["test_id"],
                           f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else None,
                           r["issue_severity"],r["issue_confidence"],r["filename"],r["line_number"],
                           (r.get("line_range") or [None])[-1],r["issue_text"],r.get("code"),r))
    return out
```

### Libraries
| lib | version | license |
|---|---|---|
| semgrep | pin exact, ~1.167.0 | **LGPL-2.1 engine**; registry rules separately Rules-License-v1.0 (do not ship) |
| bandit | 1.9.3 | Apache-2.0 |
| opengrep *(evaluate)* | latest | LGPL-2.1 (restores free cross-file taint) |

### Gotchas
OSS taint single-file only; registry-rule licensing trap; `--metrics=off` alone insufficient (also kill version-check); bare registry shorthand fetches; **`scan` exit 0 even with findings** (parse JSON); `yaml.load` only dangerous without a safe Loader; Bandit has no taint + FPs (gate `-ll`/`-ii`); pin+vendor wheels (`pip download semgrep bandit -d ./wheelhouse`); `extra.dataflow_trace` only on `mode: taint`; sink default `exact:true` (subexpressions aren't sinks) vs sources/sanitizers `exact:false`.

### `RUNTIME-CHECK` / low-confidence
- GH #8793/#9805 don't *prove* metrics-off-alone leaks (#9805 is "cannot-reproduce") — treat the dual-disable as belt-and-suspenders; the no-egress sandbox is the real guarantee.
- Registry rule counts (2,800/20,000) are order-of-magnitude only — don't quote as fact.

---

## Component 4 — training-rung5 (QLoRA SFT + DPO calibration, Unsloth + TRL on Blackwell)

**Final approach: TWO-STAGE.** **Stage A** = QLoRA SFT on a conversational dataset bundling all 3 objectives (triage/cross-file taint reasoning, calibration/FP-suppression, patching/output-schema). **Stage B** = a short **DPO** preference pass (chosen=validated finding, rejected=hallucinated finding) on the Stage-A adapter — SFT only raises P(target) and does **not** down-weight plausible-but-wrong findings (the FP failure mode). Use **DPO** with paired data from the validation layer, **KTO** if you only have unpaired binary labels (`this_finding_was_real: true/false` — cheaper to harvest), **ORPO** only to fold preference into SFT in one run.

### Install (Blackwell sm_120, air-gap-stageable)
```bash
uv pip install -U vllm --torch-backend=cu128     # pulls torch 2.7+ cu128; do NOT let it pull cu126
uv pip install unsloth unsloth_zoo bitsandbytes
pip install -U "triton>=3.3.1"                    # transformers updated separately — don't conflate
# Blackwell: export TORCH_CUDA_ARCH_LIST=12.0 if kernels misbehave; xformers OPTIONAL (SDPA fallback)
# After ANY torch upgrade: rm -rf /tmp/unsloth_compiled_cache/
# Air-gap: pip download / wheelhouse on a networked box, install --no-index offline.
```

### KEY API truths (verified)
- `FastLanguageModel.from_pretrained(model_name, max_seq_length=…, dtype=None, load_in_4bit=True)` — `max_seq_length` is **Unsloth's** arg.
- **TRL `SFTConfig` field is `max_length`, NOT `max_seq_length`** (the #1 trap). `dataset_text_field`/`packing`/`assistant_only_loss`/`completion_only_loss` live on `SFTConfig`.
- `SFTTrainer(model=…, processing_class=tokenizer, …)` — `tokenizer=` is deprecated-but-aliased. Conversational `{messages:[...]}` rows are **auto-templated** (no `formatting_func`).
- Response-only masking: `SFTConfig(assistant_only_loss=True)` needs `{% generation %}` tags (TRL auto-patches **Qwen3** only) **OR** Unsloth `train_on_responses_only(trainer, instruction_part, response_part)` applied **after** trainer construction. **Use the Unsloth wrapper for Devstral/Mistral** (template lacks generation tags).

### Corrections applied (override draft) — these are load-bearing
- **CRITICAL — the bnb-4bit repo does NOT exist.** `unsloth/Devstral-Small-2-24B-Instruct-2512-unsloth-bnb-4bit` and `...-2512-bnb-4bit` both 401. The **only** non-GGUF Unsloth Devstral-2 repo is `unsloth/Devstral-Small-2-24B-Instruct-2512`, whose config is **`quant_method='fp8'`**. Do **not** hardcode the fake bnb-4bit name into any air-gap copy script.
- **CRITICAL — architecture mismatch.** Devstral-2512 (both `mistralai/` and `unsloth/`) is **`Mistral3ForConditionalGeneration`** with a `ministral3` text_config — a **multimodal/vision** model, NOT plain `MistralForCausalLM`. Unsloth's own doc says to take the **Ministral-3 (vision) notebook** and change the model name to `unsloth/Devstral-Small-2-24B-Instruct-2512`. Consequences: (a) load the FP8 repo and let Unsloth re-quantize to 4-bit on the fly (Unsloth detects FP8); (b) `FastLanguageModel` may route to the VLM loader — verify it returns a trainable text model; (c) SFTTrainer's VLM path may engage — for VLMs TRL says set `max_length=None` (usually moot for text-only audit data, but be aware the collator differs). **This is the single biggest thing to smoke-test before committing the recipe** (`RUNTIME-CHECK`).
- **2505 vs 2512 are different architectures.** `mistralai/Devstral-Small-2505` is `MistralForCausalLM` (plain text, bf16, classic `[INST]`) — a **clean QLoRA target** and the right BF16 fallback, but **older/text-only/non-vision**, so calibration differs from 2512. Make the choice intentional. (Note: the draft also mislabeled the 2025 predecessor — the real *next-gen* release tag is `Devstral-Small-2507`; `2505` is the clean text-only one to fall back to here.)
- **Devstral-2512 template DOES contain `[INST]`/`[/INST]`** (verified, 2× each, in a heavily-customized Unsloth Jinja with strftime/date logic), so `train_on_responses_only('[INST]','[/INST]')` is plausible — **but** given issue #1262's `[INST]` double-masking bug, the label-decode sanity check is **mandatory**.
- **Qwen2.5 + `assistant_only_loss`:** TRL only confirms **Qwen3** auto-patch. For Qwen2.5-Coder prefer the Unsloth wrapper `train_on_responses_only('<|im_start|>user\n','<|im_start|>assistant\n')`, or verify the Qwen2.5 template carries generation tags first.

### Model choice on 32GB
Load the **FP8** `unsloth/Devstral-Small-2-24B-Instruct-2512` and let Unsloth re-quantize to NF4 on the fly (do **not** QLoRA the FP8 path expecting bnb-4bit to read it — bnb-4bit expects a bf16/fp16 source; Unsloth handles the FP8→4bit conversion). Clean fallbacks: `mistralai/Devstral-Small-2505` + `load_in_4bit=True` (bf16, valid), or `unsloth/Qwen2.5-Coder-32B-Instruct-bnb-4bit` (real NF4 repo, confirmed). VRAM: Devstral-2 24B QLoRA @8K ≈ **20–26GB** (`RUNTIME-CHECK` estimate; vision tower adds pressure); Qwen2.5-Coder-32B @8K tight (`bs=1`, `gradient_checkpointing='unsloth'`, maybe 6K ctx). 7B proxy for fast iteration only.

### Code sketch
```python
# ===== stage_a_sft.py =====
import torch
from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

BASE="unsloth/Devstral-Small-2-24B-Instruct-2512"   # FP8 repo; Unsloth re-quantizes to 4bit on the fly
# BF16 fallback: "mistralai/Devstral-Small-2505" (+load_in_4bit=True) | reliable: "unsloth/Qwen2.5-Coder-32B-Instruct-bnb-4bit"
MAXLEN=8192
model, tok = FastLanguageModel.from_pretrained(model_name=BASE, max_seq_length=MAXLEN, dtype=None, load_in_4bit=True)
# RUNTIME-CHECK: assert this returned a trainable text CausalLM, not a frozen VLM-only wrapper.
model = FastLanguageModel.get_peft_model(model, r=32, lora_alpha=32, lora_dropout=0, bias="none",
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    use_gradient_checkpointing="unsloth", random_state=3407)
ds = load_dataset("json", data_files="train.jsonl", split="train")   # rows: {"messages":[...]}
cfg = SFTConfig(output_dir="out/sft", max_length=MAXLEN, packing=False,   # max_length NOT max_seq_length
    per_device_train_batch_size=2, gradient_accumulation_steps=8, num_train_epochs=2,
    learning_rate=2e-4, lr_scheduler_type="cosine", warmup_ratio=0.03, optim="adamw_8bit",
    weight_decay=0.01, bf16=True, logging_steps=5, save_steps=100, seed=3407)
trainer = SFTTrainer(model=model, processing_class=tok, train_dataset=ds, args=cfg)
trainer = train_on_responses_only(trainer, instruction_part="[INST]", response_part="[/INST]")  # Devstral
# MANDATORY: decode one batch; assert non -100 label spans == assistant content only (issue #1262).
trainer.train()
model.save_pretrained("out/sft_adapter"); tok.save_pretrained("out/sft_adapter")
model.save_pretrained_gguf("out/sft_gguf", tok, quantization_method="q4_k_m")  # local serving

# ===== stage_b_dpo.py =====
from unsloth import FastLanguageModel, PatchDPOTrainer
PatchDPOTrainer()
from trl import DPOTrainer, DPOConfig
from datasets import load_dataset
model, tok = FastLanguageModel.from_pretrained("out/sft_adapter", max_seq_length=8192, dtype=None, load_in_4bit=True)
model = FastLanguageModel.get_peft_model(model, r=32, lora_alpha=32,
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    use_gradient_checkpointing="unsloth", random_state=3407)
pref = load_dataset("json", data_files="pref.jsonl", split="train")  # {prompt,chosen,rejected}
DPOTrainer(model=model, ref_model=None, processing_class=tok,        # ref_model=None → frozen base as ref
    args=DPOConfig(beta=0.1, max_length=8192, max_prompt_length=4096,
        per_device_train_batch_size=1, gradient_accumulation_steps=8, num_train_epochs=1,
        learning_rate=5e-6, optim="adamw_8bit", lr_scheduler_type="cosine", warmup_ratio=0.1,
        bf16=True, logging_steps=5, output_dir="out/dpo")).train()
model.save_pretrained_merged("out/final_16bit", tok, save_method="merged_16bit")  # → vLLM offline
```

### Data record formats (all conversational `{messages}`)
- **Obj 1 (triage/taint):** system="SovereignSec auditor, strict JSON"; user=code + `SAST_HITS:[…]`; assistant=`{"findings":[{id,cwe,file,line,sink,source,taint_path:[…],confidence,verdict:"true_positive"}]}`.
- **Obj 2 (calibration / hard-negative):** same shape, safe-looking code → assistant=`{"findings":[],"verdict":"no_vulnerability","reason":"parameterized via ORM; SAST hit is FP"}`.
- **Obj 3 (patch/schema):** assistant=`{"finding":{…},"patch":"--- a/views.py\n+++ b/views.py\n@@ …"}`.
- **DPO `pref.jsonl`:** `{"prompt":[…],"chosen":[{"role":"assistant","content":"<validated or findings:[]>"}],"rejected":[{"role":"assistant","content":"<hallucinated>"}]}`.

### Save / serve
`save_pretrained` (adapter); `save_pretrained_merged(..., save_method="merged_16bit")` (vLLM); `save_pretrained_gguf(..., quantization_method="q4_k_m"|"q8_0"|"f16")` (llama.cpp — pre-stage llama.cpp for air-gap). `push_to_hub_*` are **online-only** — skip for sovereign deploy.

### Libraries / licenses
unsloth (Apache-2.0/AGPL-aware — verify the exact license at pin time, `RUNTIME-CHECK`), unsloth_zoo, trl (Apache-2.0), bitsandbytes (MIT), triton (MIT), torch cu128 (BSD-3). Base models: Devstral Apache-2.0; Qwen2.5-Coder (check its license tag).

### Gotchas
`SFTConfig.max_length` not `max_seq_length`; `processing_class` not `tokenizer`; don't QLoRA expecting bnb to read FP8 (Unsloth converts); Devstral template has no generation tags → use the wrapper; #1262/#2771 masking bugs → decode-and-check; clear `/tmp/unsloth_compiled_cache/` after torch upgrade; pin cu128 (not cu126); `packing=False` for an auditor (packing leaks cross-sample context into taint reasoning); DPO `ref_model=None` uses frozen base, keep LR 5e-6..1e-6, 1 epoch, `beta=0.1`; everything offline except first model pull (`HF_HUB_OFFLINE=1` + pre-cache), GGUF export (needs llama.cpp), `push_to_hub_*`.

### `RUNTIME-CHECK` / low-confidence
- **Whether `FastLanguageModel` cleanly loads FP8 Mistral3-2512 for QLoRA without a vision-only/incompatible path — biggest smoke test.**
- Exact VRAM at 8K/`bs1-2` on 32GB (vision tower unaccounted) — measure with `nvidia-smi`.
- `max_seq_length`-to-`SFTConfig` failure mode (ignored vs TypeError) varies by TRL version — just use `max_length`.
- DPO/KTO-beat-SFT-hard-negatives is sound design judgment, not a single-source fact.

---

## Component 5 — serving-agent-L4 (local vLLM + offline agentic audit loop)

**Final approach.** One persistent **vLLM** OpenAI-compatible server on the RTX 5090 serving **Devstral-Small-2 base + your QLoRA adapter** via `--enable-lora`. Devstral is the default because it has **first-class native tool-calling** (`--tool-call-parser mistral`); Qwen2.5-Coder tool-calling is **broken** in vLLM (gotcha). Agent loop = **raw Python ReAct on the `openai` SDK** pointed at `127.0.0.1:8000/v1` — **no LangChain/LlamaIndex/OpenHands** (hidden prompts, telemetry/network defaults = egress risk, version churn, obscured audit trace). Drive the **outer loop over Semgrep (L3) findings** (deterministic worklist), bounded step budget per finding; never let the LLM free-roam the repo.

### Launch (corrected)
```bash
VLLM_ALLOW_RUNTIME_LORA_UPDATING=1 \
vllm serve mistralai/Devstral-Small-2-24B-Instruct-2512 \
  --served-model-name devstral \
  --tool-call-parser mistral --enable-auto-tool-choice \
  --tokenizer-mode mistral \
  --enable-lora --max-lora-rank 32 --max-loras 2 \
  --lora-modules '{"name":"auditor","path":"/models/qlora-auditor","base_model_name":"devstral"}' \
  --max-model-len 65536 --kv-cache-dtype fp8 \
  --gpu-memory-utilization 0.92 --host 127.0.0.1 --port 8000
```
- Per-request adapter select: put the **LoRA name** (`"auditor"`) in the `model` field; the base repo id → base model with no adapter (assert the served name in tests).
- Dynamic LoRA: `POST /v1/load_lora_adapter` / `/v1/unload_lora_adapter` (needs the env var; flagged not-for-prod, fine for air-gapped single box). Static = `--lora-modules` at launch.
- Bind `127.0.0.1` → zero egress.

### Corrections applied (override draft)
- **Drop the Mistral-format trio by default.** The 2512 model card does **not** use `--config-format mistral --load-format mistral`; 2512 ships standard HF config/tokenizer/safetensors. Keep `--tool-call-parser mistral --enable-auto-tool-choice` (confirmed). **Keep `--tokenizer-mode mistral`** — the Mistral tokenizer path (mistral-common, `[TOOL_CALLS]`/`[TOOL_RESULTS]`) needs it for correct tool-call formatting (vLLM #44911 serves it with that flag). The card's example uses `--tensor-parallel-size 2`; on a single 32GB 5090 the 24B-FP8 fits at **TP=1** — drop TP=2.
- **Devstral-2512 is multimodal (Vision).** Operationally: (a) **known bug — broken on vLLM 0.22.1** (`MistralCommonImageProcessor … no attribute 'fetch_images'`) while **0.21.0 works** — pin/verify your vLLM version (`RUNTIME-CHECK`); (b) the image tower consumes VRAM competing with KV cache → cap `--max-model-len` well below 256k.
- **Structured-output request API is stale.** `extra_body={'guided_json':…,'guided_decoding_backend':…}` is **deprecated**; all `guided_*` unified under one field → `extra_body={'structured_outputs': {'json': SCHEMA}}`. The **`response_format={'type':'json_schema','json_schema':{'name':…,'schema':…,'strict':True}}` path is still valid and recommended** (the `emit_final()` sketch is fine as-is).
- **CLI backend flag is stale.** `--guided-decoding-backend` deprecated → `--structured-outputs-config.backend xgrammar`. Default is **`auto`** (vLLM picks xgrammar/guidance per-request), not a hard xgrammar default.
- **Blackwell install is over-optimistic.** The stable PyPI wheel doesn't pin torch tightly for sm_120; the resolver can pull a cu130 torch whose ABI mismatches vLLM's cu128 kernels → "no kernel image" / sm_120 errors. **Install torch first from the cu128 index** (`--index-url https://download.pytorch.org/whl/cu128`) or use `vllm/vllm-openai:latest` Docker, then verify `torch.cuda.get_device_capability()==(12,0)` and a tiny generate works before assuming success. `TORCH_CUDA_ARCH_LIST=12.0` + `VLLM_FLASH_ATTN_VERSION=2` (FA3 unsupported on Blackwell) are correct.
- **FP8 KV-cache caveat:** `--kv-cache-dtype fp8` gives the **memory** win (real, validated on Blackwell) but the full FP8 *attention-compute* path needs FA3, which Blackwell lacks (you're on FA2) — don't expect FA3-level FP8 attention throughput.
- **256k won't fit 32GB** alongside a 24B-FP8 model → start 32k–65k; chunk long repos at the agent layer.

### Tool schema + loop (runnable)
```python
TOOLS = [
 {"type":"function","function":{"name":"read_file","description":"Read a narrow line range.",
   "parameters":{"type":"object","properties":{"path":{"type":"string"},
     "start_line":{"type":"integer","minimum":1},"end_line":{"type":"integer"}},"required":["path"]}}},
 {"type":"function","function":{"name":"get_definition","description":"Resolve symbol→def via L1 graph.",
   "parameters":{"type":"object","properties":{"symbol":{"type":"string"},"from_file":{"type":"string"}},"required":["symbol"]}}},
 {"type":"function","function":{"name":"ast_query","description":"Structural query → file:line hits (L1).",
   "parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}},
 {"type":"function","function":{"name":"grep","description":"Regex search, capped.",
   "parameters":{"type":"object","properties":{"pattern":{"type":"string"},"path_glob":{"type":"string"}},"required":["pattern"]}}},
 {"type":"function","function":{"name":"run_semgrep","description":"Semgrep OSS+custom → findings JSON (L3).",
   "parameters":{"type":"object","properties":{"path":{"type":"string"},"ruleset":{"type":"string"}},"required":["path"]}}},
 {"type":"function","function":{"name":"run_tests","description":"Run suite in sandbox.",
   "parameters":{"type":"object","properties":{"selector":{"type":"string"}}}}},
 {"type":"function","function":{"name":"propose_patch","description":"Propose unified-diff (does NOT apply).",
   "parameters":{"type":"object","properties":{"finding_id":{"type":"string"},"unified_diff":{"type":"string"}},"required":["finding_id","unified_diff"]}}},
 {"type":"function","function":{"name":"validate","description":"Prove finding/patch in sandbox (L5).",
   "parameters":{"type":"object","properties":{"finding_id":{"type":"string"},"unified_diff":{"type":"string"}},"required":["finding_id"]}}},
]
FINDING_SCHEMA = {"type":"object","properties":{
  "finding_id":{"type":"string"},"cwe":{"type":"string"},"owasp":{"type":"string"},
  "file":{"type":"string"},"line":{"type":"integer"},
  "severity":{"enum":["critical","high","medium","low","info"]},
  "confidence":{"type":"number","minimum":0,"maximum":1},
  "taint_path":{"type":"array","items":{"type":"string"}},
  "validated":{"type":"boolean"},"patch_diff":{"type":"string"}},
  "required":["finding_id","cwe","file","line","severity","confidence","validated"]}

import json
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="EMPTY")
MODEL = "auditor"
DISPATCH = {"read_file":tools.read_file,"get_definition":tools.get_definition,"ast_query":tools.ast_query,
            "grep":tools.grep,"run_semgrep":tools.run_semgrep,"run_tests":tools.run_tests,
            "propose_patch":tools.propose_patch,"validate":tools.validate}

def triage_finding(seed, step_budget=12):
    msgs=[{"role":"system","content":SYS_PROMPT},
          {"role":"user","content":f"Confirm/reject, find taint path, patch, validate:\n{json.dumps(seed)}"}]
    for _ in range(step_budget):
        r=client.chat.completions.create(model=MODEL,messages=msgs,tools=TOOLS,
            tool_choice="auto",temperature=0.0,max_tokens=1024)
        m=r.choices[0].message; msgs.append(m.model_dump(exclude_none=True))
        if not m.tool_calls: break
        for tc in m.tool_calls:
            out=clamp(DISPATCH[tc.function.name](**json.loads(tc.function.arguments)))  # truncate big outputs
            msgs.append({"role":"tool","tool_call_id":tc.id,"content":json.dumps(out)})
            if tc.function.name=="validate" and out.get("verdict")=="pass":
                return emit_final(msgs,seed)
    return emit_final(msgs,seed)

def emit_final(msgs, seed):   # constrained decode → guaranteed schema (response_format path is valid)
    r=client.chat.completions.create(model=MODEL,
        messages=msgs+[{"role":"user","content":"Emit the final finding object."}],
        response_format={"type":"json_schema","json_schema":{"name":"finding","schema":FINDING_SCHEMA,"strict":True}},
        temperature=0.0,max_tokens=1536)
    return json.loads(r.choices[0].message.content)

def audit_repo(repo_path):
    seeds=DISPATCH["run_semgrep"](path=repo_path,ruleset="owasp+custom")  # deterministic worklist
    return [triage_finding(s) for s in seeds["findings"]]
```
Context mgmt: tools return **line-ranged slices + AST summaries** (never whole files); rolling scratchpad, evict tool outputs older than N steps; per-finding step budget (~12); global token budget; terminate on validate-pass / validate-fail-twice / budget exhaustion. Separate "act" turns (tools) from the "emit" turn (json_schema) — mixing free tool calls + strict schema in one turn is fragile.

### Data formats
OpenAI Chat Completions over HTTP to `127.0.0.1:8000/v1`. Requests: `messages[]`, `tools[]`, `tool_choice='auto'`; strict emits via `response_format={'type':'json_schema',…}` (or `extra_body={'structured_outputs':{'json':schema}}`). Adapter routing via `model`. Tool results = `role='tool'` JSON-content messages. LoRA admin = `POST /v1/{load,unload}_lora_adapter` (`{lora_name,lora_path}`). Final artifact = list of `FINDING_SCHEMA` objects.

### Libraries
| lib | version | license |
|---|---|---|
| vllm | pin & verify on sm_120 (0.21.0 works, 0.22.1 broken for 2512) | Apache-2.0 |
| openai SDK | ≥1.x | Apache-2.0 |
| torch | cu128 (≥2.7) | BSD-3 |
| xgrammar | bundled | Apache-2.0 |
| semgrep OSS | (called as a tool) | LGPL-2.1 |

### Gotchas
Qwen2.5-Coder tool-calling broken (#32926) → if you fall back to Qwen, drive every call through `structured_outputs`, not the tools API; omitting `--tool-call-parser mistral` → malformed tool JSON; 256k won't fit 32GB; separate act/emit turns; dynamic-LoRA env-var gating; adapter selected by name in `model`; `--max-lora-rank` ≥ trained rank (default 16 → set 32); no heavyweight frameworks; Semgrep-seeded worklist (no free-roam).

### `RUNTIME-CHECK` / low-confidence
- **Exact min vLLM version that ships working cu128/sm_120 wheels AND supports the 2512 vision processor — pin and test a specific version (0.21.0 known-good, 0.22.1 known-broken).**
- Whether FP8 base + adapter + chosen `--max-model-len` fits 32GB at `util=0.92` (vision tower adds pressure) — measure empirically.
- spheron.network blog is third-party — don't rely on it for flags; use the HF card + vLLM docs.

---

## Component 6 — validation-L5 (the "prove it" gate)

**Final approach.** A deterministic, offline, binary gate run **after** L1–L4, backed by a **dynamic oracle** (not static agreement). Four oracle backends behind one interface, all from local Docker images pinned by **`@sha256` digest**, each run **N=5** with unanimity required (else quarantine as flaky/inconclusive). **The LLM is NOT in the L5 trust path** — it only *proposes*; L5 is a deterministic program (never let the model self-grade).

- **(1) OWASP BenchmarkJava** — used **only** as a SAST-accuracy *calibration harness* for your Semgrep+rules layer (compute TPR/FPR/Youden over the labeled Java corpus to set confidence thresholds). NOT a Python runtime oracle. BenchmarkPython is **v0.1 preliminary** → flag any Python-Benchmark numbers low-confidence.
- **(2)/(3)/(4) Dynamic patch oracles** — Juice Shop, DVWA, your own seeded Flask/Django/FastAPI apps — the real L5. Pattern: spin vuln container at pinned digest → **exploit pre-patch, assert success** → apply patch, rebuild/reload → **re-exploit, assert failure** → run **full existing suite + differential tests** to catch the ICSE-2026 plausible-but-wrong patch. **Pass iff: exploit-now-fails AND full-suite-passes AND differential-tests-pass.**

### Oracle specifics
- **Juice Shop:** `GET /api/Challenges` → `{"status":"success","data":[{id,key,name,category,difficulty,description,solved(bool),…}]}`. Server-side cheat-detection auto-flips `solved` on real exploitation (no POST). Read `solved` per `key`.
- **DVWA:** `security` cookie level `low|medium|high|impossible` (also `$_SESSION['security']`); set via `POST /security.php` with `security=<level>` + `user_token` CSRF, carry `security`+`PHPSESSID` cookies. Reference patches on disk: `vulnerabilities/<vuln>/source/{low,medium,high,impossible}.php`.
- **Your own Python app:** the framework-specific OWASP-Top-10 oracles you fully control (boot vuln→exploit fires→patch→exploit fails→suite+differential).

### Scoring
Benchmark Score = **Youden's J = TPR − FPR**, ×100 (perfect=100, chance=0, can be negative). A flag counts as TP/FP **only if it matches the test's intended CWE** — map your detector's CWE output to Benchmark's before comparing.

### Corrections applied (override draft) — load-bearing
- **CRITICAL — air-gap claim wrong.** `docker run --network none` creates only loopback, **no NAT** → **`-p` published ports are unreachable even from localhost**. For air-gap: (a) put target containers on a **custom internal bridge** (`docker network create --internal sovsec-l5`) so they have no egress route but the analyzer-on-the-same-network can reach them, **or** (b) keep `-p` on a normal bridge and **block egress at the host firewall / drop the default route**, then verify zero egress externally. Only the analyzer side can be `--network none`, and only if it reaches targets via a shared user-defined network.
- **arXiv 2506.11697 mis-titled.** Real title: *"SoK: Automated Vulnerability Repair: Methods, Tools, and Assessments"* (introduces the Vul4C benchmark, C/C++/Java) — a general AVR landscape source, **not** specifically about if-condition/plausible overfit patches. For the if-condition/plausible-overfit framing, cite the **ICSE-2026 NIER** paper ("The Undecidability of Overfitting in APR").
- **DVWA default is `impossible`, not `low`.** `config.inc.php.dist` sets `default_security_level = getenv('DEFAULT_SECURITY_LEVEL') ?: 'impossible'`. **Always explicitly set the level** before each exploit; never assume `low`.
- **`impossible.php` ≠ "just parameterized."** `high` *also* uses PDO prepared statements; `impossible` adds `is_numeric`/`intval` type-locking, `rowCount()==1`, anti-CSRF token, `httponly`+`SameSite=Strict`. Treat impossible as the gold reference but don't equate "parameterized = impossible-only."
- **Juice Shop reset mechanism:** default persistence is **file-based SQLite** at `data/juiceshop.sqlite` (Sequelize) wiped/recreated by `data/datacreator.ts` on **every** server start (also clears in-memory MarsDB). `challenges.yml` only defines challenge **metadata**; solved-state lives in the SQLite Challenges table. Fresh container = reset, but via datacreator-on-boot, not "challenges.yml is the live store."
- **Juice Shop official compose port is `4280`** (`http://localhost:4280`), not 80 — align your base URL if you adopt upstream compose. (Manual `-p 80:80` is fine.)
- **`solved` reflects the detector heuristic firing, not a guaranteed-clean exploit** → **hard requirement: always pair the solved flag with an independent impact assertion** (e.g. assert sensitive data actually returned), so a patch that merely silences the detector signature can't pass L5.
- **CSV example row:** use verified canonical rows (`BenchmarkTest00001,pathtraver,true,22`; `…,hash,true,328`; `…,trustbound,true,501`) — verify any specific row against the live CSV before hard-coding.

### Code sketch (key parts)
```python
import csv, requests
from dataclasses import dataclass, field
from collections import Counter

def load_benchmark_expected(csv_path):   # header line starts with '#'
    exp={}
    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].lstrip().startswith("#"): continue
            name,cat,real,cwe = row[0].strip(),row[1].strip(),row[2].strip().lower(),int(row[3])
            exp[name]={"category":cat,"real":real=="true","cwe":cwe}
    return exp

def benchmark_score(expected, detected):  # detected[name]=set(cwe ids flagged)
    tp=fp=tn=fn=0
    for name,gt in expected.items():
        flagged = gt["cwe"] in detected.get(name,set())
        if gt["real"]: tp+=flagged; fn+=(not flagged)
        else:          fp+=flagged; tn+=(not flagged)
    tpr=tp/(tp+fn) if (tp+fn) else 0.0; fpr=fp/(fp+tn) if (fp+tn) else 0.0
    return {"TP":tp,"FP":fp,"TN":tn,"FN":fn,"TPR":tpr,"FPR":fpr,"youden_score":round((tpr-fpr)*100,2)}

def deterministic_verdict(run_once, n=5):
    votes=[run_once() for _ in range(n)]; c=Counter(votes)
    return {"verdict":votes[0],"flaky":False,"votes":votes} if len(c)==1 \
           else {"verdict":None,"flaky":True,"votes":votes}   # inconclusive → don't score

JS="http://localhost:3000"
def js_challenge_solved(key):
    r=requests.get(f"{JS}/api/Challenges",timeout=10); r.raise_for_status()
    for ch in r.json()["data"]:
        if ch["key"]==key: return bool(ch["solved"])
    raise KeyError(key)
# REQUIRED: pair solved==True with an independent impact assertion (e.g. data actually leaked).

@dataclass
class PatchOracleResult:
    exploit_pre:bool   # MUST be True on vuln code
    exploit_post:bool  # MUST be False after patch
    suite_passed:bool  # no regression
    differential_passed:bool  # legit inputs work + N mutated exploit variants all blocked
    verdict:bool=field(init=False)
    def __post_init__(self):
        self.verdict = (self.exploit_pre and not self.exploit_post
                        and self.suite_passed and self.differential_passed)
```
Determinism: pin every image `@sha256`; fresh container per attempt; fix RNG seeds; use explicit **health-check polling** (not `sleep`); bound every request with a timeout; N=5 unanimity. DVWA CSRF: scrape `user_token` from each page's HTML or POSTs are silently rejected (looks like the patch "worked").

### Data formats
- **Benchmark CSV** `expectedresults-1.2.csv`: `#`-prefixed header line, then `testname,category,real(true|false),cwe(int)`.
- **Scorecard:** per-CWE + overall `{TP,FP,TN,FN,TPR,FPR,score=Youden*100}`.
- **Juice Shop:** JSON above; read `solved` per `key`.
- **DVWA:** state = `security` cookie + session; per-level source on disk.
- **Python oracle verdict:** `{exploit_pre(=True), exploit_post(=False), suite_passed, differential_passed, verdict}`.
- **Docker pin:** `image@sha256:<64hex>`.

### Libraries / licenses
| lib | version | license |
|---|---|---|
| requests | ≥2.32 | Apache-2.0 |
| docker (engine+CLI) | 27.x | Apache-2.0 |
| pytest | ≥8 | MIT |
| OWASP BenchmarkJava | 1.2 | **GPL-2.0** (dev-only harness — do not ship) |
| OWASP Juice Shop | pin `@sha256` | MIT |
| DVWA | pin `@sha256` | **GPL-3.0** (dev/test oracle only — do not ship) |

### Gotchas
"Tests pass ≠ fixed" is **structural** (require full suite + differential, never `exploit_post==False` alone); Benchmark is Java-only at runtime; `solved` = detector firing (pair with impact assertion); persistent state must reset between runs; DVWA CSRF token per page; **`--network none` breaks `-p`** (use internal bridge); digest pinning covers only the image (fix seeds, poll health, bound timeouts); air-gap needs ONE online setup pass (Docker pulls, Maven/npm/composer caches) then `--network none`/firewall-blocked; LLM never in the trust path.

### `RUNTIME-CHECK` / low-confidence
- Pull current Juice Shop `key` strings live from `/api/Challenges` or `challenges.yml` at build time (keys change across versions) — don't hard-code.
- BenchmarkPython numbers are low-confidence (v0.1).
- Verify any specific CSV row against the live file before hard-coding.

---

## Component 7 — synthetic-data (generate-and-verify pipeline + SFT mix)

**Final approach.** Matrix-driven generate-and-verify, fully offline after a one-time mirror of generator weights + `nvidia/Nemotron-SFT-SWE-v2` + the `semgrep/semgrep-rules` repo (registry shorthand `p/python` and `--config auto` phone home). A local model on vLLM iterates `product(CWE × {Django,Flask,FastAPI} × idiom × sanitizer-decoy)` — **the matrix is the diversity engine**. Each call returns a **vuln+fixed PAIR** (same app, one delta) + spec (planted lines, source_expr, sink_expr, CWE, pytest exploit). **Triple-AND verification gate** (discard the whole pair on any disagreement). **Assembly:** render each verified pair into 3 records, MinHash-LSH dedup (on the **vuln file only**), chronological + source-disjoint split (hold whole CWE×idiom cells eval-only), interleave a subsampled Nemotron slice for tool-loop shape (objective c), minority.

### Generation
```bash
HF_HUB_OFFLINE=1 vllm serve mistralai/Devstral-Small-2-24B-Instruct-2512 \
  --tokenizer-mode mistral --config-format mistral --load-format mistral \
  --tool-call-parser mistral --enable-auto-tool-choice
# single 32GB 5090: 24B-FP8 fits at TP=1 — drop --tensor-parallel-size 2 from the card example.
```
Framing avoids teaching bad patterns: "realistic code a junior would ship with exactly ONE planted CWE-X, plus a matched SECURE variant." Use guided decoding (next item) so output is parseable.

### Verification gate (triple-AND — with corrected positive gate)
1. **static-positive** = Semgrep (custom taint + python pack) **OR** Bandit flags the planted CWE within ±2 of the planted line on the vuln file. *(Correction: draft required AND; Bandit has shallow taint and misses many web CWEs → AND would silently discard many valid pairs. Use OR on the positive side. The dynamic gate already enforces real exploitability.)*
2. **static-negative** = same tools do **NOT** flag the fixed file. *(Keep strict — single highest-value gate for FP suppression.)*
3. **dynamic** = the generated exploit **PASSES on vuln** and **FAILS on fixed** inside a sandbox.

### Offline commands
```bash
semgrep scan --config ./semgrep-rules/python --config ./rules/custom_taint/ \
  --json --metrics=off --disable-version-check --no-git-ignore --timeout 0 PATH
bandit -r PATH -f json -o bandit.json   # or programmatic: BanditManager(BanditConfig(),'file')...
# sandbox (see L5 correction on --network none):
docker run --rm --network none --read-only -v S:/app:ro vuln-sandbox pytest /app/exploit_test.py
# fallback: firejail --net=none --rlimit-as ...
HF_DATASETS_OFFLINE=1  # datasets.load_dataset('nvidia/Nemotron-SFT-SWE-v2', split='train')
```
*(Note: the sandbox here runs the exploit **inside** the container against an app in the same container, so `--network none` is fine — distinct from L5 where the analyzer must reach a `-p`-published port. Keep that distinction.)*

### Corrections applied (override draft)
- **Model id:** `mistralai/Devstral-Small-2-24B-Instruct` does **not** resolve → use `mistralai/Devstral-Small-2-24B-Instruct-2512`. (The draft's "BF16 fallback Devstral-Small-2505" is the clean text-only fallback; the next-gen 2025 tag is `Devstral-Small-2507`.)
- **Keep `--tokenizer-mode mistral`** for correct tool-call formatting (mistral-common `[TOOL_CALLS]`/`[TOOL_RESULTS]`); 24B-FP8 fits TP=1 on 32GB → drop TP=2. *(See L4: the `--config-format/--load-format mistral` flags are not required for 2512; harmless if kept, but the canonical 2512 path omits them.)*
- **Dedup reference + params:** bigcode `near_deduplication` does **not** use datasketch (it rolls its own MinHash; defaults `num_perm=256`/`threshold=0.7`/`ngram=5`). Keep **datasketch** as the impl (cite `ekzhu.com/datasketch/lsh.html`), cite bigcode only for the 5-gram-shingle methodology. **Consider `threshold=0.7`** (more aggressive) given exploit families survive MinHash with renamed vars.
- **Structured-output param migration:** prefer `response_format={'type':'json_schema','json_schema':{…}}` (or offline `SamplingParams(structured_outputs=StructuredOutputsParams(json=schema))`) over `extra_body={'guided_json':…}` (on the deprecation path). Pin vLLM and verify the param name at build time.
- **Static-positive gate = OR, not AND** (above).

### Mistral/Devstral tool format (confirmed — for the agentic record)
Assistant tool-call `arguments` is a **JSON STRING** (not object); tool-result message is `role:'tool'` with **both** `name` and `tool_call_id`; serve with `--tool-call-parser mistral --enable-auto-tool-choice`; let `tokenizer.apply_chat_template(messages, tools=...)` emit the `[TOOL_CALLS]`/`[TOOL_RESULTS]` tokens — **never hand-write those tokens into JSONL**.

### Record formats (1 verified pair → 3 records)
- **(a) taint-trace:** system="Auditor: trace source→sink→sanitizer, emit finding JSON"; user=vuln code in a python fence; assistant=reasoning + json fence `{finding:true, cwe, file, line, source, sink, sanitized:false, severity:high, confidence:0.95}`.
- **(b) calibration-negative (on the FIXED file):** system="Auditor: do NOT report safe code"; user=fixed code; assistant=`{finding:false, cwe:null, reason:"parameterized; no taint path", severity:none, confidence:0.9}`.
- **(c) agentic:** top-level `tools=[semgrep_scan(path:string)]`; messages = system; user "Entry: app.py"; assistant content + `tool_calls=[{id:call_1,type:function,function:{name:semgrep_scan,arguments:<JSON STRING>}}]`; `role:tool` msg `{name:semgrep_scan, tool_call_id:call_1, content:<JSON STRING of trimmed results>}`; assistant final finding JSON.

Each record carries `_meta{cwe,fw,idiom,gen_ts}`. **Split** sorts by `gen_ts`, holds last 10% + reserved CWE×idiom cells eval-only.

### Nemotron-SFT-SWE-v2 (confirmed)
256,254 rows (209,976 Agentless + 46,278 OpenHands trajectories); columns `messages, tools, uuid, license, used_in, metadata`. **CC-BY-4.0** (attribution to NVIDIA **required**; bundles Apache/MIT/BSD code subsets). General SWE-bench repair, **not** security-specific → use **only** for tool-use loop shape (objective c); subsample ~5–10k OpenHands trajectories; reformat `messages+tools`; keep a **minority** so it doesn't dilute the security signal.

### Mix / volume (design targets)
~45% trace / 30% negative / 25% agentic; target **15–25k verified PAIRS** → ~45–75k records after 1:1:1 render, + ~5–10k Nemotron samples. *(All `RUNTIME-CHECK` — design choices, tune by ablation.)*

### Libraries
| lib | version | license |
|---|---|---|
| vllm | pin, sm_120-verified | Apache-2.0 |
| semgrep | pin | LGPL-2.1 (rules: write your own) |
| bandit | 1.9.3 | Apache-2.0 |
| datasketch | latest | MIT |
| datasets (HF) | latest | Apache-2.0 |
| docker / firejail | — | Apache-2.0 / GPL-2.0 |

### Gotchas
Triple-AND not OR for the *overall* gate (static-negative is the highest-value calibration gate); `p/python` & `--config auto` phone home (clone `semgrep-rules`, local paths, `--metrics=off --disable-version-check`); Mistral tool `arguments` is a JSON string + tool msg needs name+tool_call_id; code-Jaccard dedup insufficient (renamed-var families survive → reserve CWE×idiom cells eval-only + chronological split); generate vuln+fixed in ONE call (matched contrast); dedup vuln file only (fixed files near-identical by construction); sandbox `--network none` + timeout + read-only (generated exploit code is adversarial); `response_format`/guided decoding required or you get markdown-fenced text that breaks `json.loads`.

### `RUNTIME-CHECK` / low-confidence
- Volume/mix targets are unbenchmarked hypotheses — tune by ablation.
- Semgrep+Bandit reliably flagging arbitrary generated CWEs at ±2 lines is an assumption — **this is why the positive gate is OR**; the strict negative + dynamic gates carry precision.
- Verify Nemotron `messages` nesting reformats cleanly with a live `load_dataset` preview before building the reformatter.

---

## Cross-cutting decisions

### Package layout
```
sscai/                      # core engine package (the product; ships)
  graph/                    # Component 2: tree-sitter + jedi + NetworkX, summary taint
  retrieval/               # graph-as-index: source→sink slice extraction for the agent
  sast/                    # Component 3: semgrep/bandit subprocess orchestration + Finding model + rules/
  agent/                   # Component 5: vLLM client, ReAct loop, tool dispatch, schemas
  validation/              # Component 6: oracle interface, Juice Shop/DVWA/own-app, Benchmark calibration
  model/                   # vLLM serve config, LoRA adapter mgmt, structured-output helpers
ft-rig/                    # fine-tune rig (build-time only; does NOT ship in the product)
  data/                    # Components 1 + 7: mining (advisory-db, CVEfixes), synthetic gen-and-verify, dedup/split
  train/                   # Component 4: stage_a_sft.py, stage_b_dpo.py, configs
  serve/                   # local vLLM launch scripts, GGUF/merged export, smoke-tests
rules/                     # YOUR OWN Semgrep rules (Rules-License-clean, ships); vendored OSS rule packs separate
wheelhouse/                # pinned offline wheels (pip download → --no-index install)
```
`sscai.sast` calls semgrep/bandit (and optionally Opengrep) as **subprocesses**, never as imports of the engine — preserving the LGPL subprocess boundary. `sscai.agent` is the only network client and binds `127.0.0.1`.

### Offline / air-gap guarantees
**One-time online setup phase**, then zero egress:
1. Clone `github/advisory-database` (`--depth 1`) + full-depth framework repos for Source-A mining.
2. Download CVEfixes Zenodo dump (DOI 10.5281/zenodo.4476563); optional MoreFixes Postgres dump.
3. Mirror generator/base weights (`HF_HUB_OFFLINE=1` after pre-cache) + `nvidia/Nemotron-SFT-SWE-v2` (`HF_DATASETS_OFFLINE=1`).
4. Clone `semgrep/semgrep-rules`; build `wheelhouse/` (`pip download … -d ./wheelhouse`); pull + digest-pin Docker images (Juice Shop, DVWA, sandbox); pre-stage llama.cpp for GGUF export; build OWASP BenchmarkJava (Maven), Juice Shop (npm), DVWA (composer) caches.

**Runtime egress controls:** Semgrep `--metrics=off` + `SEMGREP_ENABLE_VERSION_CHECK=0` + local `--config` paths; vLLM bound `127.0.0.1`; **no LangChain/LlamaIndex** (their network defaults are an egress audit liability); validation containers on a `--internal` Docker bridge or host-firewall-blocked (`--network none` only where the analyzer doesn't need a published port — see L5 vs synthetic-data distinction); `push_to_hub_*` never called in sovereign deploy. **Only genuinely-online steps:** the one-time fetches above and (if ever) regenerating CVEfixes from scratch (NVD key + GitHub token) — prefer the Zenodo dump to avoid it.

### Licensing constraints that affect what ships
- **Engine deps are clean to ship:** tree-sitter (MIT), jedi (MIT), networkx (BSD-3), vLLM/openai-SDK/xgrammar (Apache-2.0), torch (BSD-3), requests (Apache-2.0), pytest (MIT), pydriller (Apache-2.0), bandit (Apache-2.0), datasketch (MIT). Devstral base **Apache-2.0**.
- **Semgrep engine LGPL-2.1** — fine because invoked as a **subprocess** (no static link). **Semgrep registry rules are Rules-License-v1.0 (internal-use-only, no redistribution) → NEVER bundle them.** Ship only the rules you authored (`rules/`) or third-party OSS rule packs under their own license. (Opengrep is LGPL-2.1, same subprocess posture, and removes the cross-file-taint limitation for free — evaluate it.)
- **code2flow is MIT** (the GPL claim was false) — not a licensing blocker, only a technical reject.
- **Data is CC-BY-4.0** (GHSA, CVEfixes/MoreFixes, Nemotron-SFT-SWE-v2) → **attribution required**; store source + DOI per record; **gate extracted code bodies by each upstream fix-commit repo's own license before redistributing** (some are incompatible).
- **Dev/test-only, do NOT ship:** OWASP BenchmarkJava (**GPL-2.0**) and DVWA (**GPL-3.0**) — they live in `validation/` as test fixtures invoked at dev/validation time, never linked into or redistributed with the product. Juice Shop is MIT (safe even as a bundled fixture).
- **Verify before pinning (`RUNTIME-CHECK`):** Unsloth's exact license tag, psycopg (LGPL-3.0, only if MoreFixes used), and Qwen2.5-Coder's model license if you adopt the fallback.

### Cross-component `RUNTIME-CHECK` summary (smoke-test before committing)
1. **Devstral-2512 FP8 Mistral3 (vision) actually QLoRA-loads as a trainable text model under Unsloth on sm_120** (biggest unknown — Component 4).
2. **vLLM version that serves 2512 + has working cu128/sm_120 wheels** (0.21.0 known-good, 0.22.1 broken — Component 5).
3. **VRAM fit** for both training (8K, 32GB) and serving (FP8 + adapter + `--max-model-len`, vision tower pressure).
4. **Devstral `[INST]` response-masking** produces correct non-`-100` label spans (issue #1262 — Component 4).
5. **Air-gap egress = zero** under your chosen network posture (verify externally, not by trusting `--metrics=off` alone).

---

# Appendix: per-component sources & verification verdicts

## data-mining (conf=high, verify=partially_confirmed)
- https://github.com/github/advisory-database (CC-BY-4.0; layout advisories/github-reviewed/YYYY/MM/GHSA-*/GHSA-*.json verified via GitHub API)
- https://ossf.github.io/osv-schema/ (OSV field paths, reference types incl. FIX, ranges types/events, PyPI ecosystem string)
- https://api.osv.dev/v1/vulns/GHSA-qcgg-j2x8-h9g8 (real Django CVE-2024-56374 advisory confirming PyPI ecosystem, ECOSYSTEM ranges, and fix commits tagged WEB)
- https://github.com/secureIT-project/CVEfixes (code MIT, dataset CC-BY-4.0; Zenodo DOI 10.5281/zenodo.4476563)
- https://raw.githubusercontent.com/secureIT-project/CVEfixes/main/Code/collect_commits.py (exact fixes/commits/file_change/method_change column lists)
- https://pydriller.readthedocs.io/en/latest/repository.html and pydriller/domain/commit.py (Repository/traverse_commits API; ModifiedFile.changed_methods, methods_before, diff_parsed, source_code_before)
- https://arxiv.org/abs/2403.18624 (PrimeVul: dedup + chronological split rationale, label-noise findings)
- https://www.researchgate.net/publication/380828080_ReposVul (ReposVul: LLM-based tangled-commit untangling + static analysis; 6,134 CVEs incl. Python)
CORRECTIONS:
  * MoreFixes IS NOT SQLite. It ships as a PostgreSQL dump (postgrescvedumper.sql.zip, ~3.5GB compressed -> ~16GB Postgres DB), per Zenodo record 13983082. The draft groups MoreFixes under 'Source B ... self-contained CVEfixes.db queried with stdlib sqlite3' and the code sketch opens it with sqlite3.connect('CVEfixes.db'). That code works for CVEfixes (genuinely SQLite) but WILL NOT work on MoreFixes as distributed. To use MoreFixes offline you must either (a) load the SQL dump into a local PostgreSQL and query with psycopg2/psycopg, or (b) convert Postgres->SQLite. Adjust the spec to say: CVEfixes=SQLite (sqlite3), MoreFixes=PostgreSQL (psql/psycopg, local server, still zero-egress once loaded).
  * MoreFixes volume numbers are understated/wrong. Draft says '~26k+ fix commits'. Zenodo states 29,203 unique CVEs from 7,238 GitHub projects, 35,276 unique commits, 39,931 patch-commit files. Use 'roughly 29k CVEs / 35k fix commits'. Also 'successor' is an overstatement: MoreFixes describes itself as 'based on CVEfixes' (enhanced repo discovery via a modified Prospector), not a drop-in successor.
  * Shallow-clone hazard for Source A. The draft correctly uses 'git clone --depth 1' for advisory-database (fine, it is only JSON), but Source A's PyDriller reconstruction clones the TARGET framework repos (django/django, pallets/flask, etc.) and runs Repository(path, single=<sha>).traverse_commits(). PyDriller computes the diff against the commit's PARENT, so those framework repos MUST be cloned with FULL history (or at least enough depth to include each fix commit's parent). A --depth 1 clone of a framework repo would yield empty/incorrect method pairs. Add an explicit gotcha: clone framework repos full-depth (or git fetch --unshallow) before single-commit mining. Confirmed shallow-clone truncates history (git-scm docs / GitHub blog).
  * Base-model id mismatch (outside data-mining scope but referenced by the project): the HuggingFace repo is mistralai/Devstral-Small-2-24B-Instruct-2512 (date-suffixed), not mistralai/Devstral-Small-2-24B-Instruct. It is Apache-2.0, 24B dense, FP8 checkpoint, strong SWE-bench, runs on a single 24-32GB GPU. Use the exact -2512 id when pulling weights offline.
  * Minor SQL-portability note for the code sketch's str(before_change) handling: in the current CVEfixes SQLite schema before_change is a stored boolean rendered as 'True'/'False' text; the draft's lower() in ('true','before','1') is a good defensive superset, but document that for MoreFixes-on-Postgres the column comes back as a native bool, so compare with the driver's bool type rather than string-matching there.

## repo-graph-L1 (conf=high, verify=partially_confirmed)
- https://pypi.org/project/tree-sitter/ (tree-sitter 0.25.2, 2025-09-25; new Language/Parser/Query/QueryCursor API)
- https://github.com/tree-sitter/py-tree-sitter (README: Language(tspython.language()), Parser(PY), QueryCursor.captures/matches)
- https://github.com/tree-sitter/tree-sitter-python/issues/280 (v0.23.0 Language(tspython.language()) capsule change)
- https://github.com/tree-sitter/py-tree-sitter/discussions/251 (post-0.22 .so loading change)
- https://pypi.org/project/tree-sitter-language-pack/ (1.10.7, 2026-06-23, MIT, ABI-14, core 0.21-0.26, 306 langs, prebuilt wheels)
- https://github.com/grantjenks/py-tree-sitter-languages + https://pypi.org/project/tree-sitter-languages/ (unmaintained)
- https://github.com/davidhalter/jedi + https://jedi.readthedocs.io/en/latest/docs/api.html (Jedi MIT, 0.20.0 2026-05-01; Script.goto/infer/get_references/get_names signatures, Name attrs)
- https://github.com/vitsalis/PyCG (Apache-2.0, ARCHIVED 2023-11-26, Python>=3.4, JSON adjacency output)
- https://arxiv.org/pdf/2103.00587 (PyCG paper: 99.2% precision / 69.9% recall)
- https://github.com/SMAT-Lab/Scalpel + https://python-scalpel.readthedocs.io/ (Apache-2.0, 1.0beta, call graph/SSA/CFG/type inference; not on PyPI as maintained pkg)
- https://github.com/scottrogowski/code2flow + LICENSE (GPL-3.0 — viral)
- https://github.com/Technologicat/pyan (pyan3, Py3.10-3.14, heuristic AST resolver)
- https://pyre-check.org/docs/pysa-basics/ (Pysa taint model: sources/sinks/sanitizers via .pysa files, needs Pyre)
- https://github.com/python-security/pyt (PyT: CFG + fixpoint dataflow taint for Python web; abandoned)
- https://codeql.github.com/codeql-standard-libraries/python/semmle/python/dataflow/old/TaintTracking.qll/module.TaintTracking.html (TaintTracking reference for the summary-based approximation)
CORRECTIONS:
  * CODE2FLOW LICENSE IS WRONG (load-bearing error). The draft repeatedly disqualifies code2flow as GPL-3.0 'viral copyleft, contaminates a sellable product.' This is FALSE. code2flow has been MIT-licensed since an April 2021 rewrite. Verified from three independent primary sources: (a) the repo LICENSE file is verbatim MIT (Copyright 2021 Scott Rogowski); (b) PyPI metadata: license field='MIT', classifier 'License :: OSI Approved :: MIT License'; (c) the README shows a 'License MIT' badge and states 'Code2flow is licensed under the MIT license.' The draft is echoing a stale pre-2021 fact (it was LGPL before the rewrite). CORRECTION: code2flow is MIT and is NOT license-disqualified. You may still reject it on technical grounds (it is a heuristic AST-name resolver, not security-grade like the draft's other reasons for pyan3), but DELETE the GPL/licensing argument entirely. Sources: https://raw.githubusercontent.com/scottrogowski/code2flow/master/LICENSE ; https://pypi.org/pypi/code2flow/json ; https://github.com/scottrogowski/code2flow
  * tree-sitter-python HAS NO 0.25.2 (minor version mismatch). The draft's pin line implies parity but the package's latest is tree-sitter-python==0.25.0 (NOT 0.25.2). Only the core 'tree-sitter' package is at 0.25.2. The draft's actual install command leaves tree-sitter-python unpinned so it still works, but if you pin tree-sitter-python==0.25.2 it will FAIL (no such release). CORRECTION: pip install tree-sitter==0.25.2 tree-sitter-python==0.25.0 (or leave tree-sitter-python unpinned). Verified via 'pip index versions tree-sitter-python' -> latest 0.25.0; and successful install of tree-sitter==0.25.2 + tree-sitter-python==0.25.0 together.
  * SCALPEL 'NOT ON PyPI' IS IMPRECISE. The draft says SMAT-Lab Scalpel is 'NOT on PyPI as the maintained package (install from GitHub).' It IS on PyPI under the name 'python-scalpel', but only as a single stale release: version 1.0b0 uploaded 2022-12-25 (3.5 years old, no updates). The draft's underlying recommendation (do not take it as a hard dependency; it is 1.0beta with thin maintenance) is CORRECT and is in fact reinforced by the evidence. CORRECTION to wording: it is on PyPI as 'python-scalpel==1.0b0 (2022-12-25)', not absent; the maintenance/beta concern is the valid reason to avoid it. Note also: the bare PyPI name 'scalpel' is a totally unrelated, dead 2010 audio editor (BSD) -- do not pip install scalpel by mistake. Sources: https://pypi.org/pypi/python-scalpel/json ; https://pypi.org/pypi/scalpel/json ; https://github.com/SMAT-Lab/Scalpel
  * tree-sitter-language-pack version range is slightly off. The draft says it is 'compatible with core 0.21-0.26'. PyPI metadata for 1.10.7 declares 'Requires-Dist: tree-sitter>=0.23' (lower bound 0.23, not 0.21) and ships abi3 wheels for Python 3.10-3.14. The '306 languages, MIT, 1.10.7' facts are confirmed. CORRECTION: state 'requires tree-sitter>=0.23' rather than '0.21-0.26'. This is a leaner/optional item anyway (Python-only auditor should use the single tree-sitter-python wheel). Source: https://pypi.org/pypi/tree-sitter-language-pack/json
  * PyCG Python-version phrasing is loose. The draft says PyCG 'targets Python<=3.4-era' / 'Python>=3.4'. The accurate floor is python_requires>=3.4 (i.e. it RUNS on 3.4+), but its grammar/analysis predates and breaks on modern syntax (match, walrus, type-alias). Keep the practical conclusion (archived 2023-11-26, Apache-2.0, unmaintainable, breaks on new syntax) -- just phrase it as 'requires 3.4+ but its syntax support is frozen at an old era,' not 'targets <=3.4.' Sources: https://github.com/vitsalis/PyCG (archived notice + 'requires Python 3.4 or higher')

## sast-rules-L3 (conf=high, verify=partially_confirmed)
- https://docs.semgrep.dev/licensing
- https://semgrep.dev/products/community-edition/
- https://docs.semgrep.dev/writing-rules/data-flow/taint-mode
- https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- https://semgrep.dev/docs/cli-reference
- https://semgrep.dev/docs/getting-started/cli-oss
- https://github.com/semgrep/semgrep/issues/8793
- https://github.com/semgrep/semgrep/issues/9805
- https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema
- https://bandit.readthedocs.io/en/latest/formatters/json.html
- https://github.com/PyCQA/bandit/blob/main/bandit/formatters/json.py
- https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow
CORRECTIONS:
  * CRITICAL — SEMGREP SCAN EXIT CODE IS WRONG. The draft states (gotcha + code-sketch comment) that 'semgrep exits 1 when findings exist; 0 = no findings, 1 = findings present.' This is FALSE for `semgrep scan`. Per the CLI reference, `semgrep scan` finishes with exit code 0 even when findings are present — you must pass --error to get exit 1 on findings. (Exit 1-on-findings is the default only for `semgrep ci`, and for the deprecated bare `semgrep` legacy alias.) Impact: the code sketch still WORKS (it uses check=False and parses stdout regardless), but the stated rationale is wrong and any downstream logic that infers 'findings exist' from returncode==1 would silently break. CORRECTION: either rely solely on parsing the JSON results[] array (recommended, what the sketch already does) OR add --error if you want returncode to signal findings. Exit >=2 still means a real error. Source: docs.semgrep.dev/cli-reference; deepwiki semgrep scan command.
  * RULE BUG — the SQL-injection taint rule's literal-exclusion will not work as written. In rule 1, the sink uses metavariable-pattern on $Q with `pattern-not: "..."` to exclude plain string literals. Because $Q binds to a string literal (which 'may not be valid code'), Semgrep REQUIRES `language: generic` inside the metavariable-pattern to match it — without it the pattern-not is ineffective (and may error on --validate). Additionally there is a known limitation (GH #10776, open) that taint analysis under-handles literal values vs variables. CORRECTION: add `language: generic` to the metavariable-pattern, and prefer a metavariable-pattern with a positive 'must look like an f-string/concat/%-format' check rather than a fragile pattern-not on a literal. Validate every rule with `semgrep --validate --config <dir>` and unit-test with # ruleid:/# ok: before trusting it. Source: docs.semgrep.dev/writing-rules/pattern-syntax (generic-language requirement); GH semgrep/semgrep#10776.
  * SSRF rule — positional-arg bug. `pattern: requests.request(..., $URL, ...)` is fragile: requests.request's signature is request(method, url, ...) so URL is the 2nd positional arg; with leading `...` $URL can bind to the wrong argument or fail to bind. Prefer named-arg-aware patterns or `requests.request(..., url=$URL, ...)` plus the positional form `requests.request($METHOD, $URL, ...)`. Also note these are written as pattern-sinks in search-like form but the rule is mode: taint — ensure sinks are real expressions tainted data flows INTO; test against fixtures.
  * STALE VERSION PINS. (a) Bandit: draft pins '1.8.x (June 2026)'; the current release is 1.9.3 (published Jan 2026), with 1.8.x being older. Pin to a specific verified version (e.g. 1.9.3) rather than '1.8.x'. (b) Semgrep: draft pins '1.* (latest CE)'; as of June 2026 latest is v1.167.0 (2026-06-17), ~weekly cadence. Pin an EXACT version (e.g. semgrep==1.167.0) for reproducible air-gap, not '1.*'. Re-run --validate and re-test your JSON parser on every bump since extra.* JSON fields occasionally shift across minors. Source: github.com/semgrep/semgrep/releases; pypi bandit.
  * MAJOR OMISSION — evaluate OPENGREP. The draft does not mention Opengrep, which is highly material for a sovereign/air-gapped project. Opengrep (github.com/opengrep/opengrep, opengrep.dev) is a Jan-2025 LGPL-2.1 fork of Semgrep CE, backed by 10+ AppSec vendors (Aikido, Endor Labs, Jit, Orca, etc.), that RESTORES cross-function / multi-file (interprocedural, interfile) taint tracking and fingerprinting FOR FREE under LGPL-2.1 — the exact capabilities the draft says are paid-Pro-only and must be punted to L4. Same rule format, same JSON/SARIF output, drop-in compatible. For SovereignSec this means you may NOT need to rely solely on your graph+LLM for cross-file taint proofs; Opengrep can provide a deterministic cross-file candidate offline. CORRECTION: at minimum, benchmark Opengrep vs Semgrep CE for your L3; it removes both the cross-file limitation AND avoids any future Semgrep-engine licensing drift. (Rule licensing trap still applies separately — write your own rules regardless.) Source: github.com/opengrep/opengrep; opengrep.dev; infoq.com/news/2025/02/semgrep-forked-opengrep; semgrep.dev/docs/faq/comparisons/opengrep.
  * MINOR — metrics default. The draft implies metrics could leak; for completeness, `--metrics` defaults to 'auto' (sends only when --config pulls from the Semgrep server or you're logged in). With a local --config and no login, 'auto' already sends nothing — but keeping the explicit --metrics=off is correct defense-in-depth. Source: docs.semgrep.dev/cli-reference.
  * MINOR — output consistency. The canonical CLI example writes to --output /tmp/semgrep.json while the run_semgrep() sketch reads p.stdout (no --output). Both are valid but pick one: if you keep --output, read the file; if you parse stdout, drop --output. Not a correctness bug, just an internal inconsistency to clean up.
  * MINOR — deduping Semgrep vs Bandit by (cwe, file, line) is brittle: the two tools frequently report DIFFERENT line numbers (sink-call line vs source line) and Semgrep cwe is a long descriptive string ('CWE-89: Improper Neutralization...') while Bandit is 'CWE-89' — so keys will rarely collide and the 'ensemble vote' will mostly not fire. Normalize cwe to the bare 'CWE-<n>' token (extract the numeric id from Semgrep's string) and dedupe on (cwe_id, file) with a small line-window tolerance, not exact line equality.

## training-rung5 (conf=high, verify=partially_confirmed)
- https://huggingface.co/docs/trl/en/sft_trainer (TRL v1.6.0 SFTConfig/SFTTrainer: max_length, packing, completion_only_loss, assistant_only_loss, processing_class, conversational auto-template)
- https://huggingface.co/docs/trl/en/unsloth_integration (canonical Unsloth+TRL example: FastLanguageModel.from_pretrained(max_seq_length), get_peft_model target_modules, SFTConfig(max_length), save_pretrained_gguf / save_pretrained_merged)
- https://unsloth.ai/docs/blog/fine-tuning-llms-with-blackwell-rtx-50-series-and-unsloth (Blackwell install: vllm --torch-backend=cu128, unsloth unsloth_zoo bitsandbytes, triton>=3.3.1, TORCH_CUDA_ARCH_LIST=12.0, unsloth/unsloth docker)
- https://unsloth.ai/docs/basics/chat-templates (get_chat_template, standardize_sharegpt, formatting_prompts_func with apply_chat_template)
- https://github.com/unslothai/unsloth/blob/main/unsloth/chat_templates.py (CHAT_TEMPLATES keys incl mistral/qwen-2.5/qwen-3; Mistral instruction='[INST]', Qwen instruction='<|im_start|>user\n' response='<|im_start|>assistant\n')
- https://raw.githubusercontent.com/unslothai/unsloth-zoo/main/unsloth_zoo/dataset_utils.py (train_on_responses_only exact signature: trainer, instruction_part, response_part, force_match, tokenizer, return_function, num_proc, last_response_only)
- https://unsloth.ai/docs/get-started/reinforcement-learning-rl-guide/preference-dpo-orpo-and-kto (PatchDPOTrainer(), DPOTrainer/DPOConfig args, beta=0.1, ref_model=None)
- https://unsloth.ai/docs/basics/inference-and-deployment/saving-to-gguf (save_pretrained_gguf quantization_method q4_k_m/q8_0/f16)
- https://unsloth.ai/docs/models/tutorials/devstral-2 (Devstral-2 24B/123B; 24B fits ~25GB; fine-tune via Ministral-3 notebook, same arch, change model name; FP8 instruct checkpoint)
- https://huggingface.co/unsloth/Devstral-Small-2-24B-Instruct-2512-GGUF (confirms current release tag is Devstral-Small-2-24B-Instruct-2512)
- https://github.com/unslothai/unsloth/issues/5154 (Blackwell QLoRA on RTX 5090: torch cu128 kernel + compiled-cache pitfalls)
CORRECTIONS:
  * CRITICAL — HALLUCINATED MODEL REPO: `unsloth/Devstral-Small-2-24B-Instruct-2512-unsloth-bnb-4bit` DOES NOT EXIST. HF API returns 401 (nonexistent) for both that name and `...-2512-bnb-4bit`. The ONLY non-GGUF unsloth Devstral-2 repo is `unsloth/Devstral-Small-2-24B-Instruct-2512`, and its config.json shows quant_method='fp8' (NOT bnb-4bit). Do not hardcode the bnb-4bit name into any air-gap copy script — it will fail on first load. The draft's own gotcha hedges this ('confirm ... else fall back') but the code_sketch and key_apis still assert the fake name as the primary BASE; that must be removed.
  * CRITICAL — ARCHITECTURE MISMATCH the draft never accounts for: Devstral-Small-2-24B-Instruct-2512 (both the mistralai base AND the unsloth mirror) is architectures=['Mistral3ForConditionalGeneration'] with a 'ministral3' text_config — i.e. a MULTIMODAL (vision) conditional-generation model, NOT a plain MistralForCausalLM. Unsloth's OWN Devstral-2 doc says to take the *Ministral-3 (vision) notebook* and just change the model name to `unsloth/Devstral-Small-2-24B-Instruct-2512`. Consequences: (a) you load the FP8 repo and let Unsloth re-quantize to 4-bit on the fly (Unsloth detects FP8 and handles it) rather than seeking a bnb-4bit repo; (b) FastLanguageModel may route to the vision/VLM loader — verify it returns a trainable text model, or use the Ministral-3 notebook path Unsloth prescribes; (c) SFTTrainer's VLM code path may engage — the TRL doc warns to set max_length=None for VLMs to avoid truncating image tokens (for text-only audit data this is usually moot, but be aware the collator may differ).
  * Devstral-2505 vs 2512 are DIFFERENT architectures, not interchangeable 'BF16 fallback': 2505 is MistralForCausalLM (plain text, bf16, classic [INST] Mistral template) while 2512 is Mistral3ForConditionalGeneration (multimodal). The draft treats 2505 as a drop-in 'no Unsloth 4bit avail' fallback — it IS a clean QLoRA target, but it is an OLDER, text-only, non-vision model, so calibration/behavior will differ from 2512. State this explicitly so the choice is intentional.
  * Devstral-2512 chat template DOES contain [INST]/[/INST] (verified by grepping the unsloth repo's chat_template.jinja — 2x each), so train_on_responses_only(instruction_part='[INST]', response_part='[/INST]') is plausible for it. BUT the 2512 template is a heavily customized Unsloth Jinja with date/strftime logic, and given issue #1262's [INST] double-masking bug on Mistral, the label-decode sanity check is mandatory before any long run. Do not assume [INST] masking 'just works'.
  * Qwen2.5 + assistant_only_loss: TRL docs only NAME Qwen3 as auto-patched for the {% generation %} tags; Qwen2.5 is NOT confirmed auto-patched. The draft hedges this ('for Qwen2.5 verify or use the wrapper') — elevate that: for Qwen2.5-Coder, prefer the Unsloth wrapper train_on_responses_only('<|im_start|>user\n','<|im_start|>assistant\n') OR verify the Qwen2.5 template carries generation tags before relying on assistant_only_loss=True.
  * VRAM claim for 24B 'comfortably fits 32GB' is supportable but note Unsloth's Devstral-2 doc benchmarks it as fitting a 24GB L4 for INFERENCE; QLoRA TRAINING headroom at 8K ctx is plausible on 32GB but the draft's '~20-26GB' is an estimate, not a sourced figure — flag as estimate, validate empirically. Qwen2.5-Coder-32B QLoRA @8K being 'tight but fits' on 32GB is also an unsourced estimate; bs=1 + gradient_checkpointing='unsloth' + possibly 6K ctx is the right risk posture.
  * Minor: `triton>=3.3.1` is correct, but one WebFetch rendering of the Unsloth blog mislabeled a `uv pip install -U transformers` line as the 'triton' step — the actual triton step is `pip install -U "triton>=3.3.1"`. Keep transformers up-to-date separately; do not conflate.

## serving-agent-L4 (conf=high, verify=partially_confirmed)
- https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512
- https://docs.vllm.ai/en/latest/features/tool_calling/
- https://github.com/vllm-project/vllm/issues/32926
- https://github.com/hanXen/vllm-qwen2.5-coder-tool-parser
- https://docs.vllm.ai/en/stable/features/lora/
- https://github.com/vllm-project/vllm/blob/main/docs/features/lora.md
- https://docs.vllm.ai/en/latest/features/structured_outputs/
- https://docs.vllm.ai/en/stable/getting_started/installation/gpu/
- https://discuss.vllm.ai/t/vllm-on-rtx5090-working-gpu-setup-with-torch-2-9-0-cu128/1492
- https://www.spheron.network/blog/deploy-devstral-gpu-cloud/
CORRECTIONS:
  * CRITICAL — structured-output request API is STALE. extra_body={'guided_json': schema, 'guided_decoding_backend':'xgrammar'} is DEPRECATED. vLLM unified all guided_* params (guided_json/guided_regex/guided_choice/guided_grammar/guided_whitespace_pattern/structural_tag) under a single 'structured_outputs' field. New form: extra_body={'structured_outputs': {'json': SCHEMA}}. The response_format={'type':'json_schema','json_schema':{'name':...,'schema':...,'strict':True}} path the code_sketch's emit_final() uses is STILL VALID and is the recommended path — so the runnable sketch is fine, but every 'extra_body guided_json' mention in key_apis_or_commands / data_formats must be replaced. Source: https://github.com/vllm-project/vllm/blob/main/docs/features/structured_outputs.md
  * CRITICAL — CLI backend flag is STALE. --guided-decoding-backend is deprecated. The current flag is --structured-outputs-config.backend (e.g. --structured-outputs-config.backend xgrammar). Also: the default is 'auto' (vLLM picks xgrammar or guidance per-request), NOT a hard 'xgrammar default' as the draft states. xgrammar is the typical auto choice and is grammar-cached/fast, so the performance claim holds, but describe the default as 'auto'. Source: https://github.com/vllm-project/vllm/blob/main/docs/features/structured_outputs.md
  * MAJOR — the launch command in recommended_approach / key_apis_or_commands includes --tokenizer-mode mistral --config-format mistral --load-format mistral, and the gotcha asserts Devstral 'REQUIRES' that trio. The official 2512 model card does NOT use those flags. Its canonical command is exactly: vllm serve mistralai/Devstral-Small-2-24B-Instruct-2512 --max-model-len 262144 --tensor-parallel-size 2 --tool-call-parser mistral --enable-auto-tool-choice. The 2512 release ships standard HF config/tokenizer/safetensors, so the mistral-format trio is NOT required (it was needed for older 2505/2507-era Mistral-format-only repos). Drop those three flags by default; keep --tool-call-parser mistral --enable-auto-tool-choice (those ARE confirmed). Source: https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512/blob/main/README.md
  * MAJOR / unflagged by draft — Devstral-Small-2-24B-Instruct-2512 is MULTIMODAL (has Vision Capabilities per the model card); it is NOT a text-only dense coder as the project notes imply. This matters operationally: (a) a known bug breaks it on vLLM 0.22.1 (AttributeError: 'MistralCommonImageProcessor' object has no attribute 'fetch_images') while 0.21.0 works — pin/verify your vLLM version before relying on it; (b) the image tower consumes extra VRAM that competes with KV cache on the 32GB card, reinforcing the need to cap --max-model-len well below 256k. Sources: https://github.com/vllm-project/vllm/issues/44911 ; https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512/blob/main/README.md
  * MODERATE — the Blackwell install claim ('cu128 wheels are now prebuilt; just uv pip install -U vllm') is OVER-OPTIMISTIC and a known footgun. As of 2026 the vLLM stable PyPI sdist/wheel does not pin torch tightly for sm_120; the resolver can pull a cu130 torch whose ABI mismatches vLLM's compiled cu128 kernels, producing 'no kernel image is available for execution on the device' / sm_120 errors. Recommended: install torch FIRST from the cu128 index (--index-url https://download.pytorch.org/whl/cu128), or use the official Docker image vllm/vllm-openai:latest, then verify torch.cuda.get_device_capability()==(12,0) and that a tiny generate works on the 5090 before assuming success. TORCH_CUDA_ARCH_LIST=12.0 and VLLM_FLASH_ATTN_VERSION=2 (FA3 still unsupported on Blackwell) are correct. Sources: https://discuss.vllm.ai/t/vllm-on-rtx5090-working-gpu-setup-with-torch-2-9-0-cu128/1492 ; https://github.com/vllm-project/vllm/issues/13306
  * MINOR / tension to flag — --kv-cache-dtype fp8 is valid and explicitly validated on Blackwell (good call), BUT vLLM's FP8-KV-cache fast path runs the QK/ScoreV attention matmuls in FP8 only under the FlashAttention 3 backend. Since FA3 is unsupported on Blackwell (you're forced to FA2), you get the KV-cache memory savings but NOT the full FP8 attention-compute path. Keep the flag (memory win is real) but don't expect FA3-level FP8 attention throughput. Source: https://vllm.ai/blog/2026-04-22-fp8-kvcache
  * MINOR — Qwen2.5-Coder tool-calling claim is CONFIRMED and well-sourced (no native tool-call tokens; --tool-call-parser hermes silently fails; open feature request #32926; community parser hanXen/vllm-qwen2.5-coder-tool-parser uses a <tools>-tag chat template). The draft's recommendation to drive Qwen tool calls through structured-outputs instead of the tools API is sound — just update that path to the new 'structured_outputs' field per the structured-output correction above. Sources: https://github.com/vllm-project/vllm/issues/32926 ; https://github.com/hanXen/vllm-qwen2.5-coder-tool-parser
  * MINOR / confirm — these are all VERIFIED, no change needed: model identity mistralai/Devstral-Small-2-24B-Instruct-2512 (real, FP8, Apache-2.0, 68.0% SWE-bench Verified); --enable-lora --max-lora-rank --max-loras flags; --lora-modules JSON form '{"name":...,"path":...,"base_model_name":...}' (with name=path legacy fallback); per-request adapter selection by putting the LoRA name in the 'model' field (base id => base model, as the draft's 'assert the served name' gotcha warns); dynamic LoRA via POST /v1/load_lora_adapter and /v1/unload_lora_adapter gated by VLLM_ALLOW_RUNTIME_LORA_UPDATING=1 (flagged not-for-prod, fine for air-gapped single box); 256k KV will not fit on 32GB so cap --max-model-len. One note: --max-lora-rank default is 16, so the draft's 'set 32 if you trained r=16/32' is correct (must be >= trained rank). Sources: https://docs.vllm.ai/en/stable/features/lora/ ; https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512

## validation-L5 (conf=high, verify=partially_confirmed)
- https://github.com/OWASP-Benchmark/BenchmarkJava
- https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv
- https://owasp.org/www-project-benchmark/
- https://www.kiuwan.com/blog/owasp-benchmark-diy/ (Youden-index scoring)
- https://help.owasp-juice.shop/appendix/integration.html (GET /api/Challenges, solved boolean)
- https://pwning.owasp-juice.shop/companion-guide/latest/part4/integration.html
- https://github.com/digininja/DVWA (security levels, config.inc.php default_security_level, vulnerabilities/*/source/{low,medium,high,impossible}.php)
- https://conf.researchr.org/details/icse-2026/icse-2026-nier/4/The-Undecidability-of-Overfitting-in-Automated-Program-Repair (ICSE 2026 NIER: tests-pass != fixed)
- https://arxiv.org/html/2506.11697 (SoK: Automated Vulnerability Repair — plausible/if-condition overfit patches)
- https://docs.docker.com/dhi/core-concepts/digests/ (image digest pinning @sha256)
CORRECTIONS:
  * AIR-GAP CLAIM IS WRONG (load-bearing): The draft says exploit traffic to a 'localhost-published port' works while running the validator with 'docker run --network none'. It does NOT. Per docs.docker.com/engine/network/drivers/none, --network none creates only the loopback device and provides NO NAT/PAT, so -p published ports are unreachable even from localhost. CORRECTION: do not use --network none on the container you must reach via a published port. For air-gap, either (a) run target containers on a custom internal Docker bridge network (docker network create --internal sovsec-l5) so they have no egress route but the analyzer-on-same-network can reach them, or (b) keep -p on a normal bridge but block egress at the host firewall / drop the default route, and verify zero egress externally. The '--network none on the analyzer side' phrasing is the only salvageable form, and only if the analyzer reaches targets via a shared user-defined network, not via host-published ports.
  * arXiv 2506.11697 IS MISDESCRIBED: The draft cites it as 'SoK: Automated Vulnerability Repair -- plausible/if-condition overfit patches'. The actual title is 'SoK: Automated Vulnerability Repair: Methods, Tools, and Assessments' -- a systematization of AVR across vulnerability analysis / patch generation / patch validation, introducing the Vul4C benchmark (144 vulns) for C/C++ and Java. It is NOT specifically about if-condition/plausible overfit patches. Keep it as a general AVR-landscape source; for the specific 'if-condition guard / plausible patch' overfitting claim, cite the ICSE-2026 NIER paper (which IS about that) rather than attributing that framing to 2506.11697.
  * DVWA default_security_level CORRECTION: draft implies default could be 'low'. The current config.inc.php.dist sets $_DVWA['default_security_level'] = getenv('DEFAULT_SECURITY_LEVEL') ?: 'impossible' -- i.e. the shipped default is 'impossible' (env-overridable via DEFAULT_SECURITY_LEVEL). Your automation MUST explicitly set the level (cookie or POST /security.php) before each exploit; never assume 'low'.
  * DVWA PDO/parameterized-query is NOT exclusive to impossible.php: the 'high' level also uses PDO prepared statements (pdo->prepare with :id binding). The difference at 'impossible' is additional defenses (is_numeric/intval type-locking, rowCount()==1, Anti-CSRF token, httponly+SameSite=Strict). So 'impossible.php = the parameterized patch' is imprecise -- impossible.php = parameterized query PLUS strict input validation PLUS CSRF/session hardening. Treat it as the gold reference but don't equate 'parameterized = impossible-only'.
  * Benchmark CSV example row 'crypto,true,327' in the draft is not among the first rows; real early rows include 'trustbound,true,501' and 'hash,true,328'. The format is right but use verified rows (BenchmarkTest00001,pathtraver,true,22) as canonical examples; 'crypto/327' and 'hash/328' categories do exist in the corpus but verify any specific row against the live CSV before hard-coding.
  * Juice Shop persistence is more nuanced than 'in-memory/SQLite': default is FILE-BASED SQLite at data/juiceshop.sqlite (via Sequelize), re-created by data/datacreator.ts on EVERY server start (which clears the SQLite file AND the in-memory MarsDB used for reviews/orders). So 'fresh container resets state' is correct, but the reset mechanism is datacreator-on-boot wiping juiceshop.sqlite + MarsDB, not 'challenges.yml is the live state store'. challenges.yml only defines challenge metadata; solved-state lives in the SQLite Challenges table.
  * DVWA official compose publishes port 4280 (http://localhost:4280), not 80. The draft's 'docker run -p 80:80' is valid for a manual run, but if you adopt the upstream docker-compose.yml the host port is 4280 -- align your oracle base URL accordingly (don't hard-code :80).
  * Juice Shop 'solved' boolean reflects the cheat-detection/verification heuristic firing, not a guaranteed-clean exploit (the draft's own gotcha is correct and should be elevated to a hard requirement): ALWAYS pair the solved-flag oracle with an independent impact assertion (e.g. assert sensitive data actually returned in the response body) so a patch that merely stops the detector signature -- but not the real exploit -- cannot pass L5.

## synthetic-data (conf=high, verify=partially_confirmed)
- https://huggingface.co/datasets/nvidia/Nemotron-SFT-SWE-v2
- https://docs.semgrep.dev/cli-reference
- https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- https://github.com/pycqa/bandit
- https://docs.mistral.ai/capabilities/function_calling/
- https://docs.vllm.ai/en/stable/features/tool_calling/
- https://github.com/bigcode-project/bigcode-dataset/blob/main/near_deduplication/minhash_deduplication.py
CORRECTIONS:
  * MODEL ID IS WRONG (hallucinated/stale). The draft's `mistralai/Devstral-Small-2-24B-Instruct` does not resolve (HTTP 401/non-existent). The correct Devstral-2 id is `mistralai/Devstral-Small-2-24B-Instruct-2512` (the -2512 = Dec 2025 date suffix the draft dropped). The 2025 predecessor is `mistralai/Devstral-Small-2507` (the draft's stated BF16 fallback 'Devstral-Small-2505' is ALSO wrong — the real release tag is 2507, not 2505). Override both ids in the spec.
  * ADD --tokenizer-mode mistral back, and consider --config-format mistral --load-format mistral. The current 2512 model-card snippet omits --tokenizer-mode, but in practice the Mistral tokenizer path (mistral-common, [TOOL_CALLS]/[TOOL_RESULTS] tokens) requires --tokenizer-mode mistral for correct tool-call formatting; vLLM issue #44911 shows it being served with that flag. The draft's serve line keeping --tokenizer-mode mistral is therefore CORRECT and should be retained, not dropped to match the card. Canonical full line: `HF_HUB_OFFLINE=1 vllm serve mistralai/Devstral-Small-2-24B-Instruct-2512 --tokenizer-mode mistral --config-format mistral --load-format mistral --tool-call-parser mistral --enable-auto-tool-choice` (add --max-model-len and --tensor-parallel-size to taste; on a single 32GB RTX 5090 the 24B FP8 fits at TP=1, so drop --tensor-parallel-size 2 from the card example).
  * DEDUP REFERENCE MISMATCH. The draft cites bigcode-project near_deduplication as the ref for datasketch MinHashLSH, but that file does NOT use datasketch — it implements its own MinHash, and its defaults are num_perm=256 / threshold=0.7 / ngram_size=5 (not 128/0.8). The 5-gram shingle choice is corroborated; the num_perm=128/threshold=0.8 values come from datasketch's own docs, not bigcode. Keep datasketch as the impl (simpler, in-memory LSH) but cite https://ekzhu.com/datasketch/lsh.html for the API and only cite bigcode for the 5-gram-shingle methodology. Also: Jaccard>=0.8 is fairly permissive for near-dup code with renamed vars; consider 0.7 to be more aggressive given the draft's own gotcha that exploit families survive MinHash.
  * vLLM is migrating guided_* params to a unified interface: prefer response_format={'type':'json_schema','json_schema':{...}} (or SamplingParams(structured_outputs=StructuredOutputsParams(json=schema)) in offline mode) over the older extra_body={'guided_json': schema}; guided_json still works in current releases but is on the deprecation path. Pin your vLLM version and verify the exact param name at build time. Source: https://docs.vllm.ai/en/latest/features/structured_outputs.html
  * STATIC-POSITIVE GATE TOO STRICT AS 'Semgrep AND Bandit'. Bandit has shallow taint analysis and will fail to flag many web-framework CWEs that Semgrep's interfile taint catches, so requiring BOTH to fire will discard a large fraction of legitimately-vulnerable pairs (lowering yield, not precision). Recommend: static-positive = Semgrep(custom taint) OR Bandit flags at planted line; keep static-negative strict (NEITHER tool flags the fixed file) since that is the calibration-critical gate. The dynamic exploit gate already enforces real exploitability, so loosening the positive static gate to OR does not admit false positives.

