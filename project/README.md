# Adaptive Knowledge Graph-Based SIEM Investigation Framework
### with LLM-Driven Attack Story Reconstruction — research prototype

A working SOC web application that demonstrates the full pipeline

```
CICIoT2023 flows → ML detection (RF / XGBoost + SHAP) → behavioral profiles → alerts
      → LangGraph agentic investigation (8 logical agents)
      → adaptive, state-dependent evidence collection loop
      → deterministic knowledge graph (Neo4j / NetworkX)
      → attack chain reconstruction → Gemini attack story (grounded + validated)
      → evidence-backed report → React SOC dashboard (Cytoscape.js)
```

The core contribution is the **adaptive, stateful, evidence-driven investigation**: the agent decides
*what evidence to collect next* from the current investigation state (hypothesis, evidence gaps, graph),
instead of running a fixed query sequence, and every claim in the final report is traceable
**Alert → Evidence → Graph → Decision → Chain → Report claim** through evidence ids.

> **Dataset placeholder.** `DATASET_DIR=./data/raw` is empty by design. Until you copy the
> CICIoT2023 `part-*.csv` files there, everything runs on clearly-labelled **synthetic demo flows**
> (`data_source=synthetic_demo`, `provenance=synthesized`) so the whole system can be exercised.
> No number shown in demo mode describes the real dataset. See [§4](#4-switching-from-placeholder-to-the-real-dataset).

---

## 1. Quick start (no external services needed)

```bash
# Python 3.11+ and Node 20+
cd project
cp .env.example .env                         # optional: everything works with an empty .env
pip install -r requirements.txt              # ~2 min (xgboost, shap, sklearn, fastapi, langgraph, ...)
cd frontend && npm install && npm run build && cd ..

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000   (first start seeds demo data: ~20–40 s, watch the log / Settings page)
```

Development mode with hot reload (two terminals):

```bash
python -m uvicorn backend.main:app --port 8000 --reload
cd frontend && npm run dev                    # http://localhost:5173, proxies /api → :8000
```

Optional services — all read from `.env`, all degrade gracefully when empty:

| Variable | Effect when set | Fallback when empty |
|---|---|---|
| `GEMINI_API_KEY`, `GEMINI_MODEL` | LLM policy (next-action reasoning), hypothesis updates, attack narrative, TI interpretation. Model availability is verified at startup with `models.list()`. | heuristic policy (utility ranking) + template narrative; UI shows *LLM: off* |
| `MONGODB_URI` | MongoDB Atlas / local persistence | `mongomock` in-process store (data lost on restart) |
| `NEO4J_URI/USERNAME/PASSWORD` | Neo4j Aura / local knowledge graph | NetworkX in-memory graph (same API) |
| `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` | passive reputation lookups, cached | provider status `not_configured`; report says *Insufficient evidence* |

Docker (optional, never required for local dev):

```bash
docker compose up --build                     # API + built UI on :8000, uses .env
docker compose --profile local-db up --build  # + local MongoDB and Neo4j Community
```

---

## 2. What you get (dashboard pages)

| # | Page | What it shows |
|---|---|---|
| 1 | **Dashboard** | KPIs, predicted activity timeline by category, attack-type distribution, recent alerts/investigations, data-provenance banner |
| 2 | **Alerts** / detail | Severity + rationale, behavioral evidence (top features vs benign, z-scores, SHAP where computed), sample flows, *Investigate* (adaptive / heuristic / fixed baseline) |
| 3 | **Investigations** / detail | Live agent activity (SSE), gap table + candidate actions + decision trace, evidence items with on-demand record fetch, embedded graph, chain, raw LangGraph state |
| 4 | **Knowledge graph** | Cytoscape view; click any node/edge → derivation rule, evidence ids, supporting records |
| 5 | **Attack story** | Gemini/template narrative with grounding validation, 15-section report, evidence-backed claims, chain, TI (API result vs AI interpretation), ATT&CK, limitations, Markdown/PDF export |
| 6 | **Threat intel** | Passive lookups (private/documentation IPs never sent), cache, curated ATT&CK table |
| 7 | **Security events** | Paginated events with filters, per-event features & prediction (ground truth never exposed) |
| 8 | **ML models** | Model card, per-class F1, confusion matrix, RF-impurity vs RF-permutation vs XGB-gain vs SHAP, feature-reduction experiment, attack-specific behavioral profiles |
| 9 | **Evaluation** | Paired adaptive-vs-baseline runs: steps, queries, events, evidence P/R, chain recall/precision/order, claim grounding, hallucinated ids |
| 10 | **Settings** | Dataset status/inspection, non-secret config, safeguards, store counts, re-run pipeline |
| — | **Login** | Shown only when `AUTH_REQUIRED=true` (JWT, demo analyst account) |

---

## 3. Architecture

```
project/
├── backend/
│   ├── main.py                 FastAPI app: /api/*, SSE, serves frontend/dist
│   ├── config.py               Settings from .env (public_dict strips secrets)
│   ├── deps.py                 Container (store, graph, llm, mitre, runner, evaluator), JWT
│   ├── routes/                 system (health/config/auth/dataset), data (events/alerts/models/profiles/TI/MITRE),
│   │                           investigations (CRUD, stream, evidence, graph, reports, evaluation)
│   ├── agents/                 LangGraph: state.py (typed state), requirements.py (evidence-requirement table),
│   │                           policy.py (heuristic / LLM chooser), agents.py (nodes), graph.py (StateGraph wiring)
│   ├── tools/registry.py       18 tools (evidence / threat-intel / graph) with uniform result contract
│   └── services/               mongo.py, repository.py (query layer; strips ground_truth), graph_store.py
│                               (InMemory + Neo4j), mitre.py, threat_intel.py, gemini.py, runner.py,
│                               evaluation.py, reports.py, alerting.py
├── ml/
│   ├── preprocessing/          labels.py (scope table), inspect.py (streaming inspector), clean.py, subset.py
│   ├── features.py, demo_data.py, contextualiser.py (scenario synthesis), pipeline.py (CLI)
│   ├── training/train.py       RF + XGBoost, stratified 70/15/15, class weights, model card
│   ├── evaluation/metrics.py   accuracy / macro & weighted P-R-F1 / per-class / confusion / inference time
│   └── explainability/profiles.py  importance comparison, SHAP, attack-specific profiles
├── frontend/                   React 18 + Vite + react-router + Cytoscape.js + Recharts
├── data/raw/                   ← DATASET PLACEHOLDER (part-*.csv)
├── data/scenarios/scenarios.yaml   devices, attacker IPs, multi-stage templates
├── data/reports/               dataset_inspection.*, evaluation_*.json, pdf/
├── tests/unit/                 test_inspect.py (20) + test_contracts.py (13)
├── scripts/                    smoke_investigation.py, run_evaluation.py, ui_smoke.py
└── docs/                       00_ARCHITECTURE_REVIEW.md, PHASE_01_dataset_inspection.md
```

### 3.1 The eight logical agents (LangGraph nodes)

| Agent | Node(s) | Deterministic? | Role |
|---|---|---|---|
| 1 Alert Investigation | `interpret_alert` | yes | reads alert + behavioral profile, seeds hypothesis, entities, initial requirements |
| 2 Evidence Collection | `execute_tool` | yes | runs the chosen tool through the registry; records an **EvidenceItem** (ids only, never copies rows into state) |
| 3 Adaptive Evidence | `assess_gaps` → `decide_action` → `reassess` | rules + optional LLM | maintains the gap table, generates candidate actions, chooses next action, updates hypothesis, decides to stop |
| 4 Threat Intelligence | tools `check_*`, `map_attack_to_mitre` | yes | passive VT/OTX lookups (gated), curated ATT&CK mapping verified against the STIX bundle |
| 5 Knowledge Graph | `build_initial_graph`, `update_graph` | yes | applies derivation rules R1–R7; every node/edge carries `derived_by`, `evidence_ids` |
| 6 Attack Reconstruction | `reconstruct` | yes | orders Attack nodes by time, computes links (shared source/target), gaps/overlaps, distributed sources, unsupported gaps |
| 7 Attack Story | `narrate_and_report` | LLM for narrative only | Gemini narrative from compressed evidence, **grounding validator** (unknown ids/IPs/forbidden phrases → template fallback) |
| 8 Report | `narrate_and_report` | yes | 15-section report, claims with evidence ids, limitations |

Loop: `assess_gaps → decide_action → execute_tool → update_graph → reassess → assess_gaps …` until
`sufficient` (score ≥ `SUFFICIENCY_THRESHOLD` and no open critical gap), `diminishing_returns`,
`no_candidates`, `max_steps`, `budget` or `timeout`.

### 3.2 Safeguards

`MAX_INVESTIGATION_STEPS`, `MAX_EVENTS_PER_QUERY`, `MAX_TIME_WINDOW_SECONDS`, `MAX_GRAPH_NODES`,
`MAX_LLM_CALLS_PER_INVESTIGATION`, `MAX_TI_LOOKUPS_PER_INVESTIGATION`, `INVESTIGATION_TIMEOUT_SECONDS`.
The LLM can only pick among rule-generated candidates (or STOP); it never writes to the graph, never
invents evidence, and its narrative is rejected when it cites unknown evidence ids/IPs.

### 3.3 Fixed-query baseline

`mode=baseline` runs the same graph with a fixed three-query plan (events by source IP in the alert
window → other alerts sharing entities → ATT&CK mapping) and no reassessment — the comparison arm for
the evaluation.

### 3.4 Ground truth isolation

The scenario contextualiser attaches synthesized IPs/devices/timestamps and (in demo mode) multi-stage
templates to flows. The hidden `ground_truth` field is stripped at the repository layer, so no agent,
tool, prompt or API response ever sees it; only `Evaluator` reads it to compute evidence/chain recall.

---

## 4. Switching from placeholder to the real dataset

1. Copy the CICIoT2023 files (`part-*.csv`, plain or `.gz`) into `data/raw/` (or set `DATASET_DIR`).
   A subset of files is fine — the inspector reports which in-scope labels are missing.
2. Inspect first (chunked, memory-safe; writes `data/reports/dataset_inspection.{json,md}`):
   ```bash
   python -m ml.pipeline inspect
   ```
   Check: target column verified as `label`, 34 labels seen, scope coverage, missing/inf/duplicate counts.
3. Run the full pipeline (inspect → clean → capped stratified subset → train RF+XGB → SHAP/profiles →
   contextualise → ingest → alert). Runtime depends on the number of rows; the subset cap is
   `SUBSET_MAX_PER_CLASS=100000` (minority classes kept in full, seed 42):
   ```bash
   python -m ml.pipeline run            # or: Settings page → "Re-run pipeline (full)"
   ```
4. Restart the API. The provenance banners switch to `data_source=ciciot2023`; the entity/time context
   is still `provenance=synthesized` (the public CSVs contain no IPs, ports or timestamps).

Scope: 5 DDoS, 4 DoS, 5 Recon, 5 Web, DictionaryBruteForce, ARP + DNS spoofing, Benign (23 classes).
**All Mirai classes and the fragmentation/slow-rate/synonymous-IP DDoS variants and BrowserHijacking
are excluded** (`ml/preprocessing/labels.py` lists every exclusion with its reason).

---

## 5. Commands

| Task | Command |
|---|---|
| API | `python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000` |
| UI dev / build | `cd frontend && npm run dev` / `npm run build` |
| Tests (no services) | `python -m pytest tests/unit -q` |
| Pipeline | `python -m ml.pipeline run [--fast]`, `python -m ml.pipeline inspect`, `python -m ml.pipeline status` |
| One investigation from CLI | `python scripts/smoke_investigation.py [--mode baseline]` |
| Paired evaluation | `python scripts/run_evaluation.py --n 10` |
| ATT&CK bundle (optional) | `python -m backend.services.mitre download` |
| Headless UI check | `pip install playwright && python -m playwright install chromium && python scripts/ui_smoke.py` |

API docs: `http://localhost:8000/docs`. Key endpoints: `/api/health`, `/api/alerts`, `POST /api/investigations`,
`/api/investigations/{id}/stream` (SSE), `/api/graph/{id}`, `/api/graph/{id}/node?key=`,
`/api/reports/{id}[/markdown|/pdf]`, `POST /api/evaluation/run`, `/api/evaluation/grounding/{id}`.

---

## 6. Evaluation

`POST /api/evaluation/run` (or the Evaluation page / `scripts/run_evaluation.py`) picks alerts
round-robin over categories and runs each through **adaptive** and **baseline** modes, then scores:

* cost — wall time, steps, DB queries, events retrieved, LLM calls, TI lookups, graph size
* evidence quality — precision/recall of retrieved flows against the hidden scenario's attack flows
* chain quality — stage recall / precision / pairwise order agreement / completeness vs the scenario template
* report quality — claims with evidence ids, narrative grounding pass rate, unknown ids/IPs per narrative

Demo-mode results are properties of the synthetic scenarios, not of CICIoT2023.

---

## 7. Known limitations (honest list)

* Demo mode = synthetic flows generated from per-class parameter templates; the trained model's scores in
  demo mode say nothing about the real dataset.
* Network-flow features cannot show usernames, passwords, commands, payloads, files or process
  activity; reports say *Insufficient evidence / Not available from the current evidence* for those.
* ATT&CK mappings are curated class-level associations, not technique detections.
* Chain stages are attack clusters of the same source ordered by time; overlapping clusters are
  reported as *overlapping*, weak links (no shared source/target) are flagged as unsupported.
* Stages backed by fewer than three flows are marked *weak support* (possible misclassification).
* `mongomock` and the NetworkX graph are process-local; evaluation jobs are in-process threads.
* SHAP is computed on ≤300 rows per class to fit small machines; disable/raise in `profiles.py`.
* Free-tier Neo4j Aura / Atlas latency will make investigations slower than the in-memory demo.

## 8. Security & ethics

Defensive research only. No traffic is generated, no scanning or exploitation is performed; threat-intel
lookups are passive and skip private / documentation ranges. Secrets live only in `.env` (git-ignored);
the frontend never receives them.
