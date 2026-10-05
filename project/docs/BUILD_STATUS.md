# Build status — full system (2026-09-05)

| Phase (md §31) | Component | Status | Verified by |
|---|---|---|---|
| 1 | Dataset inspection (`ml/preprocessing/inspect.py`) | done, waiting for real files in `data/raw/` | 20 unit tests |
| 2–3 | Cleaning, capped stratified subset (`clean.py`, `subset.py`) | done; runs automatically in dataset mode | contract tests (demo path) |
| 4 | RF + XGBoost training, 70/15/15, class weights, model card | done | `models` collection, ML page |
| 5 | Importance comparison (RF impurity / permutation / XGB gain / SHAP), profiles, feature-reduction experiment | done | ML page, `behavior_profiles` |
| 6 | Scenario contextualiser + ingestion + alerting | done | events/alerts collections |
| 7 | Evidence repository + 18 tools with uniform result contract, ground truth stripped | done | `test_tool_layer_strips_ground_truth` |
| 8 | LangGraph state, requirements table, policy, 11 nodes | done | adaptive + baseline runs |
| 9 | Knowledge graph (NetworkX / Neo4j), rules R1–R7 | done | `test_every_graph_element_is_traceable` |
| 10 | Threat intel (VT/OTX passive, gated, cached) + MITRE | done (providers optional) | `test_threat_intel_never_queries_private_or_documentation_ips` |
| 11 | Attack reconstruction (stages, links, overlaps, distributed sources, gaps) | done | chain tab, claims |
| 12 | Gemini narrative + grounding validation + template fallback | done (Gemini optional) | `test_grounding_validator_rejects_invented_ids_and_ips` |
| 13 | 15-section report, claims → evidence ids, Markdown/PDF | done | `test_markdown_and_pdf_rendering`, `/api/reports/...` |
| 14 | FastAPI API, SSE stream, JWT (optional) | done | `test_api_surface`, curl smoke |
| 15 | React dashboard, 11 pages, Cytoscape graph with evidence inspector | done | `scripts/ui_smoke.py` — 16 routes, 0 console errors |
| 16 | Evaluation harness (adaptive vs fixed baseline + grounding metrics) | done | Evaluation page, `scripts/run_evaluation.py` |
| 17 | Docker Compose / Dockerfile / Makefile / README | done (Docker optional) | — |
| 18 | Tests | 33 passing (`python -m pytest tests/unit -q`) | — |

## Last verified numbers (DEMO MODE — synthetic flows, NOT dataset statistics)

* 15,000 synthetic flows (600/class × 23 + benign weighting) → 4,590 events → 75 alerts → 15 multi-stage scenarios.
* XGBoost test macro-F1 0.925, RandomForest 0.928 on synthetic data (primary = xgboost by the selection rule).
* Paired evaluation, 4 alerts: adaptive 5.0 steps / 314 events / evidence recall 0.867 vs baseline 3.0 / 178 / 0.732;
  chain stage recall 1.0 both; 100 % of claims carry evidence ids; 0 unknown ids/IPs per narrative.

## Open items / known limitations

* Real CICIoT2023 files not yet present — dataset-specific claims are impossible until `python -m ml.pipeline inspect` runs on them.
* Gemini / VT / OTX / Atlas / Aura are not configured in this sandbox; the code paths exist and degrade gracefully but the LLM policy and TI enrichment were not exercised end-to-end here.
* Weak stages (< 3 flows) and overlapping stages are reported as such rather than hidden.
* `ml/pipeline.py` holds the ingestion event list in RAM (fine for the capped subset; stream in batches for larger caps).
* Evaluation jobs and the mongomock store are process-local.
