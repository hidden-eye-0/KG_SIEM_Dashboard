# Architecture & Feasibility Review

## Adaptive Knowledge Graph-Based SIEM Investigation Framework with LLM-Driven Attack Story Reconstruction

**Document type:** Design review (Phase 0). No application code is produced in this document.
**Date:** 2026-09-05
**Status:** Awaiting confirmation of the decisions listed in Section 19 before Phase 1 begins.

---

## 0. Environment facts measured before writing this review

Everything in this table was *measured* in the working sandbox, not assumed.

| Item | Measured value | Consequence for the design |
|---|---|---|
| CICIoT2023 files in workspace | **None found** (`find` for `*.csv/*.parquet/*.zip/*ciciot*` returned nothing) | No dataset statistics are stated as fact anywhere in this document. Phase 1 cannot start until files are provided. |
| OS / Python / Node | Debian 13, Python 3.13.14, Node 20.20.2, npm 10.8.2 | All planned Python packages publish wheels for 3.13 (checked on PyPI: xgboost 3.4.1, shap 0.52.0, scikit-learn 1.9.0, langgraph 1.2.11, google-genai 2.22.0, neo4j 6.3.0, pymongo 4.18.0, fastapi 0.141.1). |
| CPU / RAM / disk | 2 vCPU, 1.9 GiB RAM, ~20 GB free | Full-dataset in-memory training is impossible here; chunked streaming + a stratified, capped experimental subset is mandatory (Section 9). |
| Docker | Not installed | `docker-compose.yml` will be provided for the user's own machine; in the sandbox, MongoDB/Neo4j must run as plain binaries or be remote (Section 18). |
| Java | OpenJDK 11 | Neo4j 5.x needs Java 17, Neo4j 2025.x needs Java 21 → a JDK download is required for in-sandbox Neo4j, or use Neo4j Aura Free / local Docker on the user's machine. |
| Network | PyPI, npm, fastdl.mongodb.org, dist.neo4j.org, generativelanguage.googleapis.com all reachable | Dependencies and DB binaries can be fetched; Gemini API is reachable once a key is supplied. |
| Gemini model availability (checked 2026-09-05 on Google's model documentation) | Stable text models currently listed include `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-2.5-flash-lite`, plus the Gemini 3.x line (`gemini-3-flash-preview`, `gemini-3.1-pro-preview`, `gemini-3.5-flash`, `gemini-3.5-flash-lite`, …) | Model is never hard-coded. `GEMINI_MODEL` is read from `.env`; at startup the backend calls `models.list()` and reports whether the configured model is available. Recommended default: `gemini-2.5-flash` (stable, free-tier eligible); `gemini-3.5-flash` is the newer alternative. |

**External (unverified) information about CICIoT2023** — reported by third-party preprocessing notes, *not* measured by us, and to be confirmed in Phase 1: the public CSV release is ~169 `part-*.csv` files, ~46.7 M rows, 47 columns (46 features + `label`), 34 distinct labels, ~13 GB uncompressed, ~97.6 % attack rows. A decisive point for this design: **the public CSV feature set contains no IP addresses, ports, device identifiers or timestamps** — only statistical flow features and the label. This must be verified against the actual files, but it drives a key design decision (Section 2.3 and Decision D2).

---

## 1. Executive architecture

### 1.1 One-paragraph summary

The system is a layered SOC prototype. An **offline ML layer** (Random Forest / XGBoost on CICIoT2023 flow features) detects attacks and produces attack-specific **behavioral profiles**. A **SIEM alert layer** aggregates malicious flow predictions into alerts. A **LangGraph investigation runtime** executes eight logical agents over a **shared structured state**: it interprets the alert, extracts entities, builds a **deterministically-derived Neo4j knowledge graph**, runs an **adaptive evidence-collection loop** (gap analysis → candidate actions → policy choice → tool execution → graph update → reassessment) until a sufficiency criterion or a safeguard stops it, then reconstructs the attack chain and produces an **evidence-grounded, claim-by-claim traceable report** via Gemini. A **FastAPI** backend exposes REST + Server-Sent Events, and a **React + Cytoscape.js** SOC dashboard lets an analyst watch the investigation live, click any node/timeline entry to see its source records, and export the report.

### 1.2 Layer diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ L5  PRESENTATION      React SOC Dashboard (Vite, Router, Cytoscape.js, Recharts) │
│                       11 pages · SSE live investigation feed · evidence drawers │
├──────────────────────────────────────────────────────────────────────────────┤
│ L4  API               FastAPI · REST + SSE · JWT demo login · pagination       │
│                       never exposes secrets · all LLM/TI calls server-side     │
├──────────────────────────────────────────────────────────────────────────────┤
│ L3  INVESTIGATION     LangGraph runtime · 8 logical agents · typed state       │
│     RUNTIME           Tool registry (evidence / TI / graph / state tools)      │
│                       Policy = gap analysis → candidates → LLM/heuristic pick  │
│                       Safeguards: MAX_STEPS · MAX_EVENTS · MAX_WINDOW · MAX_NODES│
├───────────────────────────────┬──────────────────────┬───────────────────────┤
│ L2  KNOWLEDGE STORES          │                      │                       │
│  MongoDB                      │  Neo4j               │  Local MITRE ATT&CK   │
│  security_events, alerts,     │  dynamic knowledge   │  STIX bundle (offline)│
│  investigations, TI cache,    │  graph, evidence-    │  + curated mapping    │
│  behavior_profiles, reports,  │  linked edges        │  table w/ confidence  │
│  models, evaluation_runs      │                      │                       │
├───────────────────────────────┴──────────────────────┴───────────────────────┤
│ L1  DETECTION (offline ML)    preprocessing → RF/XGB → metrics → SHAP →        │
│                               behavioral profiles → model registry            │
├──────────────────────────────────────────────────────────────────────────────┤
│ L0  DATA                      CICIoT2023 CSV (chunked) → validated events →     │
│                               [context synthesis: IPs/devices/time, flagged]  │
│                               → Parquet cache + MongoDB bulk insert            │
└──────────────────────────────────────────────────────────────────────────────┘
       External (optional, passive, cached): VirusTotal · AlienVault OTX · Gemini
```

### 1.3 Design principles that shape every component

1. **Evidence-first**: every alert, graph node, edge, timeline entry, chain stage and report claim carries `evidence_ids` that resolve to MongoDB records. The UI can always drill down to raw records.
2. **Deterministic construction, LLM interpretation**: entities, relationships, timelines and chains are derived by code from structured data. The LLM chooses among *code-generated* candidate actions, interprets structured evidence, and writes narrative — it never creates graph facts or TI facts.
3. **Degrade, never fake**: if Gemini / VirusTotal / OTX / Neo4j are unavailable, the system continues using the available evidence and marks the gap explicitly (`status: unavailable` / "Not available from the current evidence").
4. **Ground truth isolation**: dataset labels and scenario identifiers are stored in a `ground_truth` sub-document that investigation tools *never* return; agents only see model predictions + features. Ground truth is used exclusively by the evaluation harness.
5. **Reproducibility**: fixed seeds, recorded dataset file list + hashes, model versions, prompt versions, budget parameters and policy mode are stored with every investigation and evaluation run.
6. **Bounded cost**: streaming/chunked I/O, capped queries, compressed LLM context, cached TI, a hard per-investigation budget.

---

## 2. Complete data flow

### 2.1 Offline pipeline (Phases 1–6)

```
CICIoT2023 part-*.csv (N files)
   │  chunked read (pandas, chunksize≈250k, float32 downcast, usecols)
   ▼
[A1] Dataset Inspector ──► data/reports/dataset_inspection.json   (files, rows, cols, dtypes,
   │                                                              NaN/inf, duplicates, label counts)
   ▼
Label normaliser ──► raw label → {attack_type, attack_category, in_scope}  (Mirai → excluded)
   │
   ▼
Stratified subset builder ──► data/processed/subset.parquet  (per-class caps, seed, manifest.json)
   │
   ▼
[A2] Preprocessor ──► cleaned features (inf→NaN→median impute, dedupe, dtype map, feature manifest)
   │
   ├──► Splitter (stratified 70/15/15, seed) ──► train/val/test parquet
   │
   ├──► Trainer (RF, XGB; class-weighted) ──► ml/artifacts/{model_version}/model.joblib, model_card.json
   │
   ├──► Evaluator ──► metrics.json (acc, P/R/F1 macro+weighted, per-class, confusion, latency)
   │
   ├──► Explainer (RF importance, permutation importance, XGB gain, SHAP TreeExplainer on stratified sample)
   │        └──► behavior_profiles.json ──► MongoDB.behavior_profiles
   │
   ▼
Scenario Contextualiser (Section 2.3) ──► flows + synthesized {timestamp, source_ip, destination_ip,
   │                                                     device_id, scenario_id, stage_id}  [flagged]
   ▼
Bulk ingester ──► MongoDB.security_events (insert_many, ordered=False, batches of 5–10k) + indexes
   │
   ▼
Alert generator ──► model inference per event batch → predicted_label
                    → sliding-window aggregation by (source_ip, predicted attack_type)
                    → severity rules → MongoDB.alerts
```

### 2.2 Online investigation flow (Phases 7–14)

```
Analyst clicks "Start Investigation" on Alert X (mode = adaptive | baseline)
   │
   ▼
POST /api/investigations/{id}/start ──► background task runs LangGraph graph
   │                                    every node emits AgentAction → Mongo + SSE
   ▼
[A3] interpret_alert      alert + top events + behavior profile → entities, initial hypothesis
   ▼
[A5] build_initial_graph  deterministic rules → Neo4j nodes/edges (evidence_ids on edges)
   ▼
┌─► [A6] assess_gaps       evidence requirements(hypothesis, entities, state) → open gaps
│      ▼
│   [A6] decide_action     candidates ranked by utility → LLM (or heuristic) selects 1 or STOP
│      ▼
│   execute_tool           evidence tool (Mongo) │ [A4] TI tool (VT/OTX/ATT&CK) │ graph query
│      ▼
│   record_evidence        EvidenceItem{evidence_id, record_ids, summary, relevance}
│      ▼
│   [A5] update_graph      new entities/edges/IOC/technique nodes; graph_state summary
│      ▼
│   [A6] reassess          sufficiency score, hypothesis update, termination check
│      │
└──────┘ (not sufficient AND budget remains AND candidates exist)
       │
       ▼ (sufficient | max_steps | no_candidates | diminishing_returns | budget)
[A7] reconstruct           timeline (evidence-ordered) → stages → chain (+ unsupported gaps)
   ▼
[A8] narrate_and_report    retrieve→filter→compress→structure→Gemini → claims validated
   ▼                        against evidence_ids → report (+ limitations) → Mongo.reports
GET /api/investigations/{id}/{report|graph|timeline|chain}  ──►  React pages / PDF export
```

### 2.3 Entity & temporal context — the honest handling of a dataset limitation

If Phase 1 confirms that the CSV files contain no IP/timestamp columns, the knowledge graph would have nothing to connect: a flow record is just 46 numbers and a label. The prototype therefore needs a **Scenario Contextualiser** that assigns entity and time context to real dataset flows in a transparent, reproducible way:

- **Inputs:** real CICIoT2023 flow rows (features + label untouched).
- **Scenario templates** (YAML): single-stage (e.g., "DDoS SYN flood from attacker A to device D") and multi-stage (e.g., "PortScan → DictionaryBruteForce → CommandInjection from A to D", "HostDiscovery → OSScan → VulnerabilityScan", "ARP spoofing then DNS spoofing on the same segment"). Each stage draws K real flows of the stage's label, without replacement, from the experimental subset.
- **Synthesized fields:** `timestamp` (sequential within stage, category-specific inter-arrival profile), `source_ip` / `destination_ip` (attackers from documentation ranges 203.0.113.0/24 & 198.51.100.0/24, IoT devices from 192.168.0.0/16), `device_id`, `device_type`; benign flows become background traffic between device pairs.
- **Provenance:** every event has `context.provenance = "synthesized"`; every UI page that shows IPs/times displays a banner: *"Entity and time context is synthesized for CICIoT2023 flows (the public CSV release has no IP addresses or timestamps). Feature values and attack labels are from the dataset."*
- **Ground truth for evaluation:** `scenario_id`/`stage_id` give an objective attack chain against which reconstruction completeness is measured (Section 17.E) — hidden from agents.
- **What is *not* done:** no usernames, commands, SQL strings, files or process trees are synthesized. Tools such as `get_authentication_events()` return *network flows on authentication protocols* (SSH/Telnet indicator = 1) and say so; `get_firewall_events()` returns `status: "no_source"` unless a firewall log source has been ingested (the repository is multi-source by design: `log_source` field).

If the provided files *do* contain IPs/timestamps (some redistributions differ), the contextualiser is bypassed and `context.provenance = "dataset"`. This is **Decision D2**.

---

## 3. Eight-agent architecture

All agents share one LLM client (Gemini, via `google-genai`) with role-specific prompts and structured output schemas; Agents 1, 2, 5 and 7 are **fully deterministic** (no LLM call) — the LLM is used only where reasoning/interpretation adds value (Agents 3, 6, 8; optionally 4 for TI interpretation). Every agent is a Python class with `run(state) -> state_delta`, and the LangGraph nodes are thin wrappers.

| # | Agent | Runs where | LLM? | Input | Output / state changes | Tools | Termination |
|---|---|---|---|---|---|---|---|
| 1 | **Data Ingestion Agent** | offline CLI (`ml/pipeline ingest`) | No | dataset directory | `dataset_inspection.json`, validated event batches, ingestion stats (`ingestion_runs`) | chunked reader, schema validator, malformed-record quarantine, bulk inserter | all files processed or error budget hit |
| 2 | **Preprocessing & Behavioral Analysis Agent** | offline CLI (`ml/pipeline train`, `explain`, `predict`) | No (optional: LLM writes human-readable profile summaries, clearly marked "AI interpretation") | processed parquet | cleaned data, splits, trained models, metrics, feature importance, SHAP, `behavior_profiles`, predictions for alert generation | sklearn/xgboost/shap | pipeline complete |
| 3 | **Alert Investigation Agent** | LangGraph node `interpret_alert` | **Yes** (structured output) | alert, ≤50 representative events, behavior profile for the predicted type, existing related alerts | `entities`, `current_hypothesis` {statement, category, type, confidence, alternatives}, initial `missing_evidence`, first `agent_log` entry | `get_alert`, `get_alert_events`, `get_behavior_profile`, `search_alerts` | one pass |
| 4 | **Threat Intelligence Agent** | LangGraph tool-node `execute_ti` (invoked when the policy selects a TI action) | Optional (interpretation of API results, kept separate from raw results) | indicator list (public IPs, domains, hashes if present) | `threat_intelligence[indicator]` = {raw API results, normalised reputation, status}, IOC entities, ATT&CK mappings for the hypothesis type | `check_virustotal_ip/domain/hash`, `check_otx_indicator`, `map_attack_to_mitre`, TI cache | each selected indicator processed or provider unavailable |
| 5 | **Knowledge Graph Agent** | LangGraph nodes `build_initial_graph`, `update_graph` | **No** | new evidence items, entities, TI results | Neo4j nodes/relationships (deterministic derivation rules, Section 6.4), `graph_state` summary, MAX_GRAPH_NODES enforcement | `create_graph_node`, `create_graph_relationship`, `query_related_nodes`, `get_attack_subgraph` | all deltas applied |
| 6 | **Adaptive Evidence Collection Agent** (primary research component) | LangGraph nodes `assess_gaps`, `decide_action`, `reassess` | **Yes** for action selection & hypothesis update (heuristic fallback when no LLM) | full state | `missing_evidence`, `candidate_actions`, chosen action, `tool_history`, `confidence`, `termination_reason` | all evidence tools + TI + graph query tools via the registry; `identify_missing_evidence`, `update_investigation_state`, `mark_evidence_as_supporting` | sufficiency ≥ τ, MAX_INVESTIGATION_STEPS, no candidates, diminishing returns, error budget |
| 7 | **Attack Reconstruction Agent** | LangGraph node `reconstruct` | **No** (LLM explains the chain later in A8) | evidence, graph subgraph, TI, profiles | `attack_chain` {timeline[], stages[], relationships[], unsupported_gaps[]}, OCCURS_BEFORE/PART_OF edges | `get_attack_subgraph`, timeline builder, stage inference rules | chain built |
| 8 | **Attack Story & Report Agent** | LangGraph node `narrate_and_report` | **Yes** (narrative, recommendations) + deterministic assembly & grounding validator | compressed state (≤ ~6k tokens) | `final_report` with 15 sections, `claims[]` each with `evidence_ids`, severity justification, limitations; `reports` doc; PDF | report assembler, grounding validator, PDF renderer | report validated (or returned with `validation_warnings`) |

**Why this split:** Agents 1–2 are batch/offline (they must not run per alert); Agents 3–8 form the online loop. Agent 6 is decomposed into three LangGraph nodes so that gap analysis, action selection and reassessment are individually observable and testable — that is what makes the adaptive mechanism evaluable rather than a black box.

---

## 4. Tool architecture

### 4.1 Registry and contract

```
backend/tools/registry.py
  ToolSpec(name, category, description, args_schema: pydantic, cost_hint, requires: [mongo|neo4j|vt|otx|llm])
  ToolResult(tool, args, status: ok|empty|truncated|unavailable|error,
             records: list[dict], count: int, total_matched: int|None,
             evidence_ids: list[str], latency_ms: float, query_cost: int,
             provenance: {collection|provider, query_digest}, note: str|None)
```

Rules enforced *inside* the tool layer (so no agent can bypass them):

- `limit ≤ MAX_EVENTS_PER_QUERY`; time windows clamped to `MAX_TIME_WINDOW`; result is marked `truncated` with `total_matched` when clipped.
- `ground_truth.*` fields are projected out of every record.
- Every call is appended to `tool_history` with a content digest → traceability and evaluation counters (queries, events retrieved, latency).
- External TI tools are `async`, cached (`threat_intelligence` collection, TTL), rate-limited, and return `status: unavailable | not_configured | private_address` instead of raising.

### 4.2 Tool catalogue

| Category | Tool | Backing store | Notes |
|---|---|---|---|
| Evidence | `search_security_events(filters, time_range, limit)` | Mongo `security_events` | generic filtered search |
| Evidence | `get_events_by_ip(ip, role=src|dst|any, time_range)` | Mongo | compound index (source_ip, timestamp) |
| Evidence | `get_events_by_time_range(start, end, filters)` | Mongo | clamped to MAX_TIME_WINDOW |
| Evidence | `get_events_by_device(device_id, time_range)` | Mongo | |
| Evidence | `get_related_events(alert_id, strategy=same_source|same_target|same_pair|follow_on, window)` | Mongo | follow_on = after alert.last_seen, excluding alert's own type |
| Evidence | `get_authentication_events(ip|device, window)` | Mongo (SSH/Telnet indicator flows) | explicitly labelled "auth-protocol network flows" |
| Evidence | `get_network_events(ip|device, protocol, window)` | Mongo | |
| Evidence | `get_dns_events(ip|device, window)` | Mongo (DNS indicator flows) | |
| Evidence | `get_firewall_events(ip, window)` | Mongo `log_source=firewall` | returns `no_source` unless ingested |
| Evidence | `search_alerts(source_ip|destination_ip|category, window)` | Mongo `alerts` | related-alert correlation |
| Evidence | `get_event_aggregates(group_by, filters, window)` | Mongo aggregation | counts/distinct targets without pulling rows |
| TI | `check_virustotal_ip(ip)`, `check_virustotal_domain(domain)`, `check_virustotal_hash(hash)` | VT v3 API (passive) | cached; private/reserved IPs short-circuited |
| TI | `check_otx_indicator(type, value)` | OTX API (passive) | pulse count, tags, first/last seen if provided |
| TI | `map_attack_to_mitre(attack_type)` | local ATT&CK STIX + curated table | returns technique id/name/url + mapping confidence + rationale |
| Graph | `create_graph_node(type, key, props, evidence_ids)` | Neo4j | MERGE by key |
| Graph | `create_graph_relationship(src, rel, dst, props, evidence_ids)` | Neo4j | MERGE + evidence union |
| Graph | `query_related_nodes(node_key, depth, rel_types)` | Neo4j | |
| Graph | `get_attack_subgraph(investigation_id, time_filter, types)` | Neo4j | powers the UI |
| State | `get_investigation_state(id)`, `update_investigation_state(id, delta)` | Mongo `investigations` | checkpoint |
| State | `record_evidence(item)`, `mark_evidence_as_supporting(evidence_id, hypothesis_id, polarity)` | state + Mongo | |
| State | `identify_missing_evidence(state)` | requirement templates | returns gaps + candidate actions |

### 4.3 How the agent chooses tools

The LLM never sees free-form tool signatures alone; it sees **state-derived candidate actions** (tool + arguments + rationale + expected gain) produced by `identify_missing_evidence`, and returns a structured choice (`action_id` or `STOP`, reasoning, optional argument adjustments within limits, hypothesis update). This keeps the choice state-dependent and auditable, and lets the same loop run with a heuristic policy when no LLM key is configured (Section 10).

---

## 5. MongoDB schema

Database: `siem_kg`. All documents carry `created_at`; IDs are string ULIDs (`evt_…`, `alr_…`, `inv_…`) so they are portable across Mongo, Neo4j and the UI.

### 5.1 `security_events`

```json
{
  "_id": "evt_01J…",
  "timestamp": ISODate,
  "source_ip": "203.0.113.24",
  "destination_ip": "192.168.10.31",
  "device_id": "iot-cam-07",
  "protocol": "TCP",                       // derived from indicator columns / Protocol Type
  "log_source": "CICIoT2023",              // multi-source ready: "firewall", "auth", ...
  "features": { "flow_duration": 0.0, "Header_Length": 54.0, "Rate": 3.1, "...": "all 46 numeric features" },
  "prediction": { "label": "DDoS-SYN_Flood", "attack_type": "DDoS SYN Flood",
                  "category": "DDoS", "confidence": 0.98, "model_version": "xgb-2026-09-…" },
  "context": { "provenance": "synthesized|dataset", "generator_version": "1.0", "seed": 42 },
  "dataset": { "file": "part-00007-….csv", "row_index": 12345 },
  "ground_truth": { "label": "DDoS-SYN_Flood", "scenario_id": "scn_…", "stage_id": "stg_2" }  // NEVER returned by tools
}
```

Indexes (only these): `{timestamp:1}`, `{source_ip:1, timestamp:1}`, `{destination_ip:1, timestamp:1}`, `{device_id:1, timestamp:1}`, `{protocol:1}`, `{"prediction.attack_type":1, timestamp:1}`, `{"ground_truth.scenario_id":1}` (evaluation only).

### 5.2 `alerts`

```json
{ "_id": "alr_…", "created_at": ISODate, "first_seen": ISODate, "last_seen": ISODate,
  "attack_type": "Recon Port Scan", "category": "Reconnaissance", "predicted_label": "Recon-PortScan",
  "severity": "medium", "severity_rationale": ["base:Reconnaissance=low", "targets>=3 → +1"],
  "source_ip": "...", "destination_ips": ["..."], "device_ids": ["..."], "protocol": "TCP",
  "event_count": 412, "event_ids_sample": ["evt_…", "… (≤200)"], "confidence_mean": 0.94,
  "behavioral_evidence": { "top_features": [{"feature":"syn_flag_number","value":1.0,"profile_mean":0.97,"benign_mean":0.12,"z":3.4}], "profile_version": "…" },
  "status": "new|investigating|resolved", "investigation_ids": [] }
```

Indexes: `{created_at:-1}`, `{severity:1, status:1}`, `{source_ip:1, first_seen:1}`, `{category:1}`.

### 5.3 `investigations`

```json
{ "_id": "inv_…", "alert_id": "alr_…", "mode": "adaptive|baseline|heuristic",
  "status": "created|running|completed|failed|stopped", "started_at": ISODate, "finished_at": ISODate,
  "state": { "...": "full LangGraph InvestigationState snapshot (Section 7)" },
  "steps": [ { "step": 1, "agent": "AlertInvestigationAgent", "node": "interpret_alert", "action": "…",
               "tool": null, "args": {}, "result_summary": "…", "evidence_ids": [], "llm_used": true,
               "latency_ms": 812, "timestamp": ISODate } ],
  "metrics": { "steps": 7, "db_queries": 9, "events_retrieved": 1830, "llm_calls": 5, "ti_lookups": 2,
               "graph_nodes": 21, "graph_edges": 34, "latency_ms": 41230 },
  "config": { "budget": {"max_steps": 12, "max_events_per_query": 500, "max_time_window_s": 86400, "max_graph_nodes": 300},
              "gemini_model": "…", "prompt_version": "…", "policy": "llm|heuristic|fixed", "seed": 42 } }
```

Indexes: `{alert_id:1}`, `{status:1, started_at:-1}`.

### 5.4 `threat_intelligence` (cache + audit)

```json
{ "_id": "ti_…", "indicator": "203.0.113.24", "type": "ip|domain|hash", "provider": "virustotal|otx|mitre",
  "status": "ok|not_configured|unavailable|private_address|not_found", "fetched_at": ISODate, "expires_at": ISODate,
  "raw": { "...": "verbatim provider response (trimmed of nulls)" },
  "normalized": { "malicious_votes": 0, "harmless_votes": 0, "reputation": 0, "pulse_count": 0,
                  "first_seen": null, "last_seen": null, "tags": [], "related_domains": [], "related_hashes": [] },
  "ai_interpretation": { "text": "…", "model": "…", "generated_at": ISODate } }   // always separate from raw
```

Indexes: `{indicator:1, provider:1}` (unique), `{expires_at:1}` (TTL).

### 5.5 `behavior_profiles`

```json
{ "_id": "bp_…", "attack_type": "DoS SYN Flood", "raw_label": "DoS-SYN_Flood", "category": "DoS",
  "model_version": "…", "n_samples": 100000,
  "importance": { "rf_impurity": [["syn_flag_number",0.21],…], "rf_permutation": [...], "xgb_gain": [...],
                  "shap_mean_abs": [...] },
  "top_features": ["syn_flag_number","syn_count","Rate","Header_Length","IAT"],
  "feature_stats": { "syn_flag_number": {"class_mean":0.99,"class_std":0.05,"benign_mean":0.11,"z":4.1}, "...": {} },
  "protocol_indicators": { "TCP": 0.99, "UDP": 0.0, "HTTP": 0.0, "...": 0 },
  "profile_statement": "Behavioral evidence associated with the labelled DoS SYN Flood class: …",   // template-generated
  "created_at": ISODate }
```

### 5.6 `reports`, `models`, `dataset_stats`, `evaluation_runs`, `ingestion_runs`

- `reports`: `{ _id, investigation_id, sections{15 named sections}, claims[{claim_id, text, evidence_ids, confidence, validated}], narrative, limitations[], llm{model, prompt_version, tokens}, pdf_path, generated_at }`.
- `models`: model registry `{ version, algorithm, params, train_files_hash, class_list, metrics_ref, artifact_path, created_at }`.
- `dataset_stats`: the Phase 1 inspection output (one doc per run).
- `evaluation_runs`: `{ run_id, config, per_investigation[], aggregates{}, created_at }`.
- `ingestion_runs`: counts, malformed-record counts, durations.

---

## 6. Neo4j schema

### 6.1 Scoping model

- **Canonical entity nodes** are global (one node per IP address, device, domain, technique, IOC) so knowledge accumulates across investigations and "related alerts" can traverse shared entities.
- **Investigation-scoped nodes** (`Investigation`, `Alert`, `Attack`, `Behavior`, `EvidenceSet`) carry `investigation_id`.
- **Every relationship** carries `investigation_id`, `evidence_ids` (≤ 50 sampled) + `evidence_count`, `first_seen`, `last_seen`, `derived_by` (rule id), `confidence`.
- The per-investigation subgraph = nodes touched by relationships with that `investigation_id` (query in Section 6.5).

Community Edition compatible: every node has a `key` property with a single-property uniqueness constraint (`IP:203.0.113.24`, `Attack:inv_…:stage_1`), so no Enterprise-only node-key constraints are needed.

### 6.2 Node labels and properties

| Label | key | Properties |
|---|---|---|
| `IP` | `IP:<addr>` | address, is_private, is_reserved_doc_range, first_seen, last_seen, roles[] |
| `Device` | `Device:<device_id>` | device_id, device_type, ip, first_seen, last_seen |
| `Domain` | `Domain:<fqdn>` | fqdn, source (only from TI results) |
| `Attack` | `Attack:<inv>:<n>` | attack_type, category, predicted_label, first_seen, last_seen, event_count, confidence, alert_id, severity |
| `Alert` | `Alert:<alert_id>` | severity, category, created_at |
| `EvidenceSet` (the spec's `Event` node, aggregated) | `EvidenceSet:<evidence_id>` | tool, query_digest, count, sample_event_ids, time_range |
| `Behavior` | `Behavior:<inv>:<attack_n>` | top_features json, z_scores json, profile_version |
| `IOC` | `IOC:<provider>:<indicator>` | provider, status, reputation, malicious_votes, pulse_count, fetched_at |
| `MITRETechnique` | `MITRE:<Txxxx(.yyy)>` | technique_id, name, tactic(s), url, attack_version |
| `Investigation` | `Investigation:<inv_id>` | mode, status, started_at |
| `User`, `File`, `Process` | reserved | schema present, unused unless a log source provides them (never synthesized) |

### 6.3 Relationship types

`COMMUNICATES_WITH` (IP→IP / IP→Device), `TARGETS` (Attack→Device/IP), `GENERATES` (Attack→Alert), `PERFORMS` (IP→Attack), `ASSOCIATED_WITH` (IP→IOC), `RESOLVES_TO` (IP→Domain, only from TI passive DNS), `INDICATES` (Behavior→Attack, IOC→Attack), `PART_OF` (Attack→Investigation, Alert→Investigation), `OCCURS_BEFORE` (Attack→Attack), `MAPS_TO` (Attack→MITRETechnique), `SUPPORTED_BY` (Attack/claim→EvidenceSet), `CONNECTS_TO` / `EXECUTES` reserved for future log sources.

### 6.4 Deterministic derivation rules (no LLM involvement)

| Rule id | Trigger (structured data) | Graph effect |
|---|---|---|
| R1 | event(src, dst) in evidence | `(IP src)-[:COMMUNICATES_WITH {count, first_seen, last_seen, evidence_ids}]->(IP/Device dst)` |
| R2 | alert or evidence cluster with predicted attack_type T from src to dst set | `(IP src)-[:PERFORMS]->(Attack T)-[:TARGETS]->(Device/IP dst)`; `(Attack)-[:GENERATES]->(Alert)`; `(Attack)-[:PART_OF]->(Investigation)` |
| R3 | tool result recorded as EvidenceItem | `(EvidenceSet)`, `(Attack)-[:SUPPORTED_BY]->(EvidenceSet)` |
| R4 | behavior profile match for the attack's events | `(Behavior)-[:INDICATES {z_scores}]->(Attack)` |
| R5 | TI result `status: ok` | `(IOC)`, `(IP)-[:ASSOCIATED_WITH {provider}]->(IOC)`; domains from passive DNS → `RESOLVES_TO` |
| R6 | curated ATT&CK mapping for attack_type (validated against local STIX bundle) | `(Attack)-[:MAPS_TO {confidence, rationale}]->(MITRETechnique)` |
| R7 | two Attack nodes with same src (or same dst) and non-overlapping time, A.last_seen < B.first_seen | `(A)-[:OCCURS_BEFORE {gap_seconds}]->(B)` |
| R8 | MAX_GRAPH_NODES reached | no new nodes; edges to existing nodes still merged; `graph_state.truncated = true` |

### 6.5 Core queries (files under `graph/queries/`)

```cypher
// subgraph for an investigation
MATCH (a)-[r {investigation_id: $inv}]->(b) RETURN a, r, b LIMIT $max_nodes;

// evidence behind a node
MATCH (n {key: $key})-[r {investigation_id: $inv}]-() 
RETURN n.key AS node, collect(DISTINCT r.evidence_ids) AS evidence, collect(DISTINCT type(r)) AS rels;

// chronological attack chain for a source IP
MATCH (ip:IP {address: $ip})-[:PERFORMS {investigation_id: $inv}]->(a:Attack)
OPTIONAL MATCH (a)-[:OCCURS_BEFORE]->(b:Attack) RETURN a, b ORDER BY a.first_seen;
```

Constraints/indexes: `CREATE CONSTRAINT node_key_unique IF NOT EXISTS FOR (n:IP) REQUIRE n.key IS UNIQUE` (repeated per label); range index on `Attack(first_seen)`; relationship index on `investigation_id` where supported.

A `GraphStore` interface (`Neo4jGraphStore`, `InMemoryGraphStore` using NetworkX) lets unit tests and the evaluation harness run without a Neo4j server; the demo uses Neo4j.

---

## 7. LangGraph state design

```python
class InvestigationState(TypedDict):
    investigation_id: str
    alert_id: str
    mode: Literal["adaptive", "baseline", "heuristic"]
    alert: AlertSummary                     # compact alert view (no raw feature dump)
    current_hypothesis: Hypothesis          # {id, statement, attack_type, category, confidence,
                                            #  supporting_evidence_ids, contradicting_evidence_ids, alternatives[]}
    entities: dict[str, Entity]             # "IP:203.0.113.24" -> {type, value, role, first_seen, last_seen, evidence_ids}
    evidence: Annotated[list[EvidenceItem], operator.add]   # append-only
    missing_evidence: list[EvidenceGap]     # {gap_id, requirement_id, description, priority, status: open|resolved|unresolvable, resolved_by}
    candidate_actions: list[CandidateAction]# {action_id, tool, args, rationale, expected_gain, cost, closes_gap_ids}
    last_action: ActionRecord | None        # {action_id, chosen_by: llm|heuristic|fixed, reasoning}
    tool_history: Annotated[list[ToolCall], operator.add]
    threat_intelligence: dict[str, TIResult]
    graph_state: GraphSummary               # {node_count, edge_count, by_type, truncated, last_updated}
    attack_chain: AttackChain | None        # {timeline[], stages[], relationships[], unsupported_gaps[]}
    confidence: float
    sufficiency: SufficiencyScore           # {score, coverage, novelty_last_k, reason}
    investigation_step: int
    budget: Budget                          # limits + counters (steps, events, llm_calls, ti_calls, graph_nodes)
    termination_reason: str | None          # sufficient | max_steps | no_candidates | diminishing_returns | budget | error
    final_report: Report | None
    agent_log: Annotated[list[AgentAction], operator.add]   # UI transparency feed
    errors: Annotated[list[str], operator.add]
```

Graph wiring (`backend/agents/graph.py`):

```
START → interpret_alert → build_initial_graph → assess_gaps → decide_action
decide_action ──(action.tool in evidence tools)──► execute_evidence_tool ─┐
              ──(action.tool in TI tools)────────► execute_ti ────────────┤
              ──(action.tool in graph tools)─────► execute_graph_query ───┤
              ──(STOP)───────────────────────────► reconstruct            │
record_evidence ◄─────────────────────────────────────────────────────────┘
record_evidence → update_graph → reassess
reassess ──(continue)──► assess_gaps
        ──(stop)──────► reconstruct → narrate_and_report → END
```

- **Checkpointing:** LangGraph checkpointer persisted to MongoDB (`langgraph_checkpoints`) so a run can be resumed/inspected step by step; each node also appends an `AgentAction` that is streamed via SSE.
- **Baseline mode** uses a separate compiled graph: `interpret_alert → fixed_queries (3 predefined tool calls) → build_graph_once → reconstruct → narrate_and_report`. Same tools, same report format → fair comparison.
- **Every node contract** (input keys read, output keys written, tools allowed, max LLM calls) is declared in a table in `agents/contracts.py` and enforced by a test.

---

## 8. API architecture

FastAPI, `/api` prefix, JSON, cursor/page pagination (`page`, `page_size ≤ 200`), consistent error body `{error: {code, message, details}}`, OpenAPI docs at `/docs`. Long-running work (ingestion, investigations, evaluation) runs as background tasks with status endpoints; investigations stream progress via **SSE**.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | service + dependency status (mongo, neo4j, gemini model check, vt/otx configured) |
| GET | `/api/config` | non-secret runtime config (budget limits, model name, provenance mode) |
| POST | `/api/auth/login` · GET `/api/auth/me` | demo analyst login (JWT); credentials from env |
| GET | `/api/dataset/stats` · `/api/dataset/files` · `/api/dataset/labels` | Phase 1 inspection output |
| GET | `/api/events` · `/api/events/{id}` | paginated evidence browsing (ground truth excluded) |
| GET | `/api/alerts` · `/api/alerts/{id}` · `/api/alerts/{id}/events` | alert list (filters: severity, category, status, ip), detail, evidence |
| POST | `/api/investigations` `{alert_id, mode}` | create |
| GET | `/api/investigations` · `/api/investigations/{id}` | list / detail (state + metrics) |
| POST | `/api/investigations/{id}/start` · `/stop` | run / cancel |
| GET | `/api/investigations/{id}/stream` | SSE feed of agent actions |
| GET | `/api/investigations/{id}/steps` · `/evidence` · `/events` | transparency views |
| GET | `/api/investigations/{id}/timeline` · `/chain` | reconstruction outputs |
| GET | `/api/investigations/{id}/graph` (`?types=&from=&to=`) | Cytoscape elements JSON |
| GET | `/api/investigations/{id}/graph/nodes/{key}/evidence` | node → supporting records |
| GET | `/api/investigations/{id}/report` · `/report.pdf` | report JSON / PDF |
| GET | `/api/threat-intelligence` · `/api/threat-intelligence/{indicator}` | cached TI (raw vs AI interpretation separated) |
| GET | `/api/mitre/techniques/{id}` | local ATT&CK lookup |
| GET | `/api/models` · `/api/models/{version}` | registry + metrics + confusion matrix |
| GET | `/api/behavior-profiles` · `/api/behavior-profiles/{attack_type}` | profiles |
| GET | `/api/evaluation` · `/api/evaluation/runs/{id}` · POST `/api/evaluation/run` | research evaluation |

Security notes: CORS restricted to the frontend origin; secrets only in backend env; TI/LLM keys never leave the server; login is a demo gate, not a hardened auth system (stated in README).
## 9. ML experiment design

ML is the detection layer, not the contribution; the design goal is a *sound, reproducible, documented* baseline.

### 9.1 Label mapping (applied only after Phase 1 confirms the actual label strings)

Expected raw labels → scope. Anything not listed (all `Mirai-*`, `DDoS-ACK_Fragmentation`, `DDoS-PSHACK_Flood`, `DDoS-RSTFINFlood`, `DDoS-SlowLoris`, `DDoS-SynonymousIP_Flood`, `DDoS-ICMP/UDP_Fragmentation`) → `in_scope=false` (recorded in the inspection report, excluded from training). `BrowserHijacking` → optional (Decision D5). `BenignTraffic` → `Benign` (required as the negative class).

| Category | Conceptual type (from the brief) | Expected raw label |
|---|---|---|
| DDoS | ICMP / UDP / TCP / SYN / HTTP Flood | `DDoS-ICMP_Flood`, `DDoS-UDP_Flood`, `DDoS-TCP_Flood`, `DDoS-SYN_Flood`, `DDoS-HTTP_Flood` |
| DoS | TCP / UDP / SYN / HTTP Flood | `DoS-TCP_Flood`, `DoS-UDP_Flood`, `DoS-SYN_Flood`, `DoS-HTTP_Flood` |
| Reconnaissance | Ping Sweep, OS Scan, Host Discovery, Vulnerability Scan, Port Scan | `Recon-PingSweep`, `Recon-OSScan`, `Recon-HostDiscovery`, `VulnerabilityScan`, `Recon-PortScan` |
| Web-Based | SQL Injection, Command Injection, Backdoor Malware, Uploading Attack, XSS | `SqlInjection`, `CommandInjection`, `Backdoor_Malware`, `Uploading_Attack`, `XSS` |
| Brute Force | Dictionary Brute Force | `DictionaryBruteForce` |
| Spoofing | ARP Spoofing, DNS Spoofing | `MITM-ArpSpoofing`, `DNS_Spoofing` |

→ 22 attack classes + Benign = **23-class problem** (24 if Browser Hijacking is included), plus a 7-class category model for coarse alerting/comparison.

### 9.2 Data budget (driven by the 2 vCPU / 1.9 GiB sandbox; adjustable on a bigger machine)

- Stream *all* provided files once for inspection (Phase 1) — full counts, never a sample.
- Build a **stratified experimental subset**: per-class cap `N_max` (default 100 000; smaller classes such as the web attacks — reported by external sources as only ~1–3 k rows each — are taken in full). Reservoir-style sampling per class across chunks with a fixed seed; the manifest records exactly which (file, row_index) pairs were kept.
- Justification recorded in the model card: flood classes are near-duplicates at scale (very low intra-class variance); capping them reduces compute by >90 % while the minority classes remain complete. This is the "sampling only when scientifically justified" clause of the brief, and its effect is measured (Section 9.6).

### 9.3 Preprocessing

`inf → NaN → median impute (fit on train only)`; drop exact duplicate feature rows (count reported); float32; no scaling for tree models (a `StandardScaler` is fitted anyway and stored for the optional logistic-regression baseline); feature manifest with the 46 names (`Magnitue` kept verbatim with an alias note); column-name whitespace stripped.

### 9.4 Split and imbalance

- **Stratified 70/15/15** (train/val/test, seed 42). Justification: the subset is large enough that a held-out validation set is statistically stable, and val is needed for early stopping (XGBoost) and threshold/hyper-parameter choices without touching test. 5-fold CV is added *only* for the small web-attack classes' confidence intervals if their test counts are < 300 (reported, not silently).
- **Imbalance:** class-balanced sample weights (`balanced` for RF, `sample_weight` for XGB) + the per-class cap. SMOTE is *not* the default (synthetic flow features are hard to justify scientifically); it may be run as an ablation. Macro-F1 is the primary model-selection metric; per-class recall for minority classes is reported.

### 9.5 Models and evaluation

| Model | Settings (initial) | Purpose |
|---|---|---|
| RandomForest | 200 trees, `max_depth` tuned on val, `class_weight=balanced_subsample`, `n_jobs=-1` | primary interpretable baseline |
| XGBoost | `hist`, `max_depth` 8, `eta` 0.1, early stopping on val, sample weights | primary performance model |
| Logistic regression (optional) | scaled features | sanity baseline |

Reported: accuracy, macro/weighted precision-recall-F1, per-class table, confusion matrix (raw + normalised), inference time (per-row and per-10k batch), training time, model size; results saved to `metrics.json` and the `models` collection; figures to `ml/artifacts/<version>/figures/`.

### 9.6 Explainability → behavioral profiles (Phase 4)

For each class: RF impurity importance, RF permutation importance (val set), XGB gain, and **SHAP** (`TreeExplainer` on XGB, stratified sample ≤ 2 000 rows/class, class-specific mean |SHAP|). Agreement between methods is measured (rank-biased overlap of top-10). A **profile** = top-k features (consensus of methods), class vs benign feature statistics with z-scores, protocol-indicator rates, feature-group summary (traffic / temporal / flags / protocol / packet statistics), and a template-generated statement using the mandated phrasing ("…provide behavioral evidence associated with the labelled X class"). Feature-reduction experiment: retrain on top-10/15/20 consensus features and report the macro-F1 delta (profile quality metric).

---

## 10. Adaptive evidence-collection algorithm

### 10.1 Formalisation

- State `S_t` = (hypothesis `H`, entities `E`, evidence `V`, graph summary `G`, TI `T`, budget `B`, history `A_1..A_{t-1}`).
- **Evidence requirements** `R(H, E)`: a rule table keyed by hypothesis category/type plus generic requirements. Each requirement has: `id`, description, priority, `is_satisfied(S)` predicate, and `candidate_generators(S) → [CandidateAction]`.
- **Gap set** `Gaps_t = { r ∈ R(H,E) : ¬ r.is_satisfied(S_t) ∧ r.status ≠ unresolvable }`.
- **Candidate action** `a = (tool, args, closes_gap_ids, expected_gain, cost)`; `expected_gain = Σ priority(gap) × novelty(a)`, where `novelty` discounts actions whose query digest overlaps prior calls; `cost` from tool hints (Mongo aggregate < Mongo scan < external TI).
- **Policy** `π(S_t, Candidates_t) → a_t | STOP`: LLM (structured output: chosen `action_id`, reasoning, hypothesis update, optional bounded arg changes) — or heuristic `argmax(expected_gain / cost)` when no LLM is configured or as an ablation.
- **Sufficiency** `σ(S_t) = w1·coverage(required gaps resolved) + w2·hypothesis_confidence + w3·chain_connectivity(G)`; stop when `σ ≥ τ` (default 0.8) *and* all `priority=critical` requirements are resolved or marked unresolvable.
- **Diminishing returns:** stop if the last `k=3` actions each yielded `< ε` new evidence (novel record ids) and no new entities.

### 10.2 Pseudocode

```
def investigate(alert, mode):
    S = init_state(alert)
    S = A3.interpret_alert(S)                    # entities, H0, initial gaps
    S = A5.build_initial_graph(S)                # rules R1,R2,R4
    while True:
        gaps = requirements(S.H, S.entities).unsatisfied(S)      # A6.assess_gaps
        S.missing_evidence = gaps
        if not gaps or budget_exhausted(S) or diminishing_returns(S):
            S.termination_reason = ...; break
        cands = generate_candidates(gaps, S) - already_executed(S)
        cands = enforce_limits(cands, S.budget)                  # MAX_EVENTS_PER_QUERY, MAX_TIME_WINDOW
        if not cands: S.termination_reason = "no_candidates"; break
        a = policy(S, cands)                                     # A6.decide_action (LLM or heuristic)
        if a is STOP and sufficiency(S) >= tau: S.termination_reason = "sufficient"; break
        r = tools.execute(a)                                     # evidence | TI (A4) | graph
        S.evidence += to_evidence_items(r); S.tool_history += [a, r]
        S.entities |= extract_entities(r)
        S = A5.update_graph(S, r)                                # rules R1..R8
        S.H = reassess_hypothesis(S)                             # A6.reassess (LLM or rules); update gaps
        S.confidence, S.sufficiency = score(S)
        S.investigation_step += 1
        if S.sufficiency.score >= tau and no_open_critical(S): S.termination_reason = "sufficient"; break
        if S.investigation_step >= MAX_INVESTIGATION_STEPS: S.termination_reason = "max_steps"; break
    S = A7.reconstruct(S)
    S = A8.narrate_and_report(S)
    return S
```

### 10.3 Example requirement table excerpt (`backend/agents/requirements.py`)

| Requirement | Applies to | Satisfied when | Candidate actions |
|---|---|---|---|
| `source_history` (critical) | all | ≥1 evidence item for source IP outside the alert window | `get_events_by_ip(src, window=24h before)`, `get_event_aggregates(group_by=attack_type, src)` |
| `target_breadth` (high) | DDoS/DoS/Recon | distinct destination count known for src | `get_event_aggregates(group_by=destination_ip, src)` |
| `follow_on_activity` (critical) | Recon, Brute Force, Spoofing | events from src after alert.last_seen have been checked | `get_related_events(alert, strategy=follow_on)` |
| `precursor_activity` (high) | Web, Brute Force, DoS | events from src before alert.first_seen checked | `get_related_events(alert, strategy=same_source, window=before)` |
| `auth_protocol_activity` (high) | Brute Force, Web | SSH/Telnet flows for target checked | `get_authentication_events(target)` |
| `dns_context` (medium) | Spoofing | DNS-indicator flows on the segment checked | `get_dns_events(target)` |
| `related_alerts` (high) | all | `search_alerts` for src/dst executed | `search_alerts(source_ip=src)`, `search_alerts(destination_ip=dst)` |
| `external_reputation` (medium; low if src private) | all | TI status ≠ pending for each public indicator | `check_virustotal_ip`, `check_otx_indicator` |
| `technique_mapping` (medium) | all | ATT&CK mapping resolved for H.type | `map_attack_to_mitre` |
| `target_response` (medium) | DDoS/DoS | Drate/response behaviour for target summarised | `get_event_aggregates(group_by=protocol, dst)` |

Because the requirement set is a function of the *current* hypothesis and entities (which change as evidence arrives: a Recon hypothesis that discovers follow-on brute-force flows becomes a multi-stage hypothesis, activating `auth_protocol_activity`), the sequence of actions differs per incident — this is what distinguishes the mechanism from a fixed pipeline, and it is exactly what the evaluation in Section 17.E measures against the fixed-query baseline.

### 10.4 Safeguards (env-configurable)

`MAX_INVESTIGATION_STEPS=12`, `MAX_EVENTS_PER_QUERY=500`, `MAX_TIME_WINDOW_SECONDS=86400`, `MAX_GRAPH_NODES=300`, `MAX_LLM_CALLS_PER_INVESTIGATION=20`, `MAX_TI_LOOKUPS_PER_INVESTIGATION=10`, `INVESTIGATION_TIMEOUT_SECONDS=300`.

---

## 11. React / SOC dashboard architecture

- **Stack:** React 19 + Vite, `react-router-dom`, `axios` (via `services/api.js`), `cytoscape` (+ `cytoscape-fcose` layout), `recharts` for charts, native `EventSource` for SSE, CSS modules with a dark SOC theme (no heavy UI framework → fast, offline-friendly).
- **Dev proxy:** Vite proxies `/api` → backend, so the browser only ever talks to relative URLs; in production the FastAPI app serves the built `dist/`.
- **State:** lightweight — React Query-style hooks (`useAlerts`, `useInvestigation`, `useInvestigationStream`) built on `useEffect` + a tiny cache; no Redux.

| Route | Page | Key components |
|---|---|---|
| `/login` | Login / Landing | project summary, demo login form, dataset-provenance notice |
| `/` | Dashboard | KPI tiles (total/critical/high/medium/low, active/resolved investigations), attack-type bar, category donut, recent alerts, recent investigations |
| `/alerts` | Alerts | filterable/paginated table, severity badges, "Investigate" action |
| `/alerts/:id` | Alert Details | header facts, behavioral evidence panel (feature vs profile vs benign z-scores), feature-importance bars, related events table, TI panel, investigation status, **Start Investigation** (mode selector) |
| `/investigations/:id` | Investigation | live agent activity feed (SSE), hypothesis card, evidence collected list, evidence required (gaps) list, TI summary, graph preview, timeline strip, chain summary, conclusion; step click → tool args/result drawer |
| `/investigations/:id/graph` | Knowledge Graph | Cytoscape canvas, type filter chips, time-range slider, node detail drawer with **supporting evidence** table (raw records), edge detail |
| `/investigations/:id/timeline` | Attack Timeline | vertical chronological timeline, stage colour coding, click → source records |
| `/threat-intelligence` | Threat Intelligence | indicator table; detail shows **Actual API result** and **AI interpretation** in separate, labelled panes |
| `/investigations/:id/report` | Investigation Report | 15 sections, claim → evidence chips, limitations, "Export PDF" |
| `/analytics` | Model / Behavioral Analytics | model cards, metrics tables, confusion-matrix heatmap, per-class profile explorer (importance method comparison, SHAP bars) |
| `/configuration` | Configuration | non-secret runtime config, dependency health, budgets (read-only + editable for the demo session), dataset stats |

Shared: `EvidenceDrawer` (any evidence_id → records), `ProvenanceBanner`, `SeverityBadge`, `StatusPill`, `JsonViewer`, `Paginator`.

---

## 12. Project directory structure

```
project/
├── backend/
│   ├── main.py                 # FastAPI app factory, routers, lifespan (DB clients, model check)
│   ├── config.py               # pydantic-settings, .env, budgets
│   ├── agents/                 # graph.py (LangGraph wiring), state.py, contracts.py, requirements.py,
│   │                           # policy.py (llm/heuristic/fixed), a1_ingestion.py … a8_report.py, prompts/
│   ├── tools/                  # registry.py, evidence_tools.py, ti_tools.py, graph_tools.py, state_tools.py
│   ├── models/                 # pydantic schemas (events, alerts, investigations, reports, TI)
│   ├── services/               # mongo.py, neo4j_store.py (+ inmemory_store.py), gemini.py, virustotal.py,
│   │                           # otx.py, mitre.py, alerting.py, reporting.py (pdf), sse.py, cache.py
│   ├── routes/                 # health, auth, dataset, events, alerts, investigations, ti, models, profiles, evaluation
│   └── utils/                  # ids.py, ipaddr.py, timeutil.py, logging.py
├── frontend/
│   ├── index.html, vite.config.js, package.json
│   └── src/ components/ pages/ services/ hooks/ styles/
├── data/
│   ├── raw/                    # CICIoT2023 CSVs (git-ignored)  ← user places files here
│   ├── processed/              # parquet subset, splits, manifests
│   ├── scenarios/              # YAML scenario templates
│   └── reports/                # dataset_inspection.json, figures
├── ml/
│   ├── preprocessing/          # inspect.py, labels.py, subset.py, clean.py, split.py
│   ├── training/               # train_rf.py, train_xgb.py, registry.py
│   ├── evaluation/             # metrics.py, plots.py
│   ├── explainability/         # importance.py, shap_analysis.py, profiles.py
│   └── cli.py                  # `python -m ml.cli inspect|subset|train|explain|ingest|alerts`
├── graph/
│   ├── schema/                 # constraints.cypher, README (node/edge dictionary)
│   └── queries/                # subgraph.cypher, node_evidence.cypher, chain.cypher
├── evaluation/                 # harness.py (adaptive vs baseline vs heuristic), grounding_checker.py, report_tables.py
├── tests/                      # unit/ integration/ e2e/ fixtures/
├── scripts/                    # dev_up.sh (local mongo/neo4j), seed_demo.py, export_report.py
├── .env.example  requirements.txt  README.md  docker-compose.yml  Makefile  pytest.ini
```

---

## 13. Development phases (with exit criteria)

| Phase | Deliverable | Exit test (must pass before next phase) |
|---|---|---|
| 1 Dataset inspection | `ml/preprocessing/inspect.py`, `dataset_inspection.json`, label-scope mapping report | runs over all provided files in streaming mode; totals reconcile with `wc -l`; unit tests on a fixture CSV |
| 2 Preprocessing | subset builder, cleaner, splitter, manifests | deterministic across two runs (hash-equal parquet); no leakage (imputer fit on train only) test |
| 3 ML baseline | RF + XGB training, metrics, model registry | metrics.json produced; inference API on a batch; model reload test |
| 4 Feature importance + SHAP | importance comparison, SHAP, `behavior_profiles.json`, reduction experiment | profiles for every in-scope class; phrasing rule enforced by test |
| 5 MongoDB ingestion | contextualiser, bulk ingester, indexes, `ingestion_runs` | counts match subset; indexes present; ground-truth exclusion test |
| 6 Alert generation | inference → aggregation → severity → `alerts` | alerts for each category; every alert's `event_ids_sample` resolves |
| 7 LangGraph framework | state, contracts, graph skeleton with stub nodes, checkpointing, SSE log | graph runs end-to-end with stubs; contract test |
| 8 Investigation tools | evidence/state tools, registry, limits | limit/clamp/truncation tests; ground-truth projection test |
| 9 Threat intelligence | VT/OTX clients (async, cached, graceful), MITRE local bundle + curated mapping | unit tests with recorded fixtures; unavailable-provider behaviour test |
| 10 Neo4j graph | store interface, derivation rules, queries, constraints | rules produce expected graph on fixture; subgraph/evidence queries |
| 11 Adaptive evidence collection | requirements, candidates, policy (LLM + heuristic), sufficiency, safeguards | same alert → different action sequences under different evidence; every limit enforced; termination reasons covered |
| 12 Attack reconstruction | timeline, stages, chain, unsupported gaps | multi-stage scenario reconstructed; single-stage not forced into chain |
| 13 LLM attack story | prompts, compression, grounding validator, report assembly, PDF | claims ↔ evidence_ids validated; unsupported claim flagged in a test |
| 14 FastAPI backend | all routes, auth, pagination, SSE | API tests (httpx) per route |
| 15 React frontend | 11 pages | manual + component smoke tests; preview verified |
| 16 Integration | docker-compose, scripts, README | fresh-environment walkthrough |
| 17 Testing & evaluation | harness, tables, figures | adaptive vs baseline results reproducible with seed |
| 18 Demo scenarios | 5–6 curated scenarios + seeded DB | analyst walkthrough script |

---

## 14. Dependencies (versions verified on PyPI/npm on 2026-09-05)

**Python (`requirements.txt`, pinned ranges):** `fastapi~=0.141`, `uvicorn[standard]~=0.52`, `pydantic~=2.13`, `pydantic-settings~=2.15`, `python-dotenv~=1.2`, `pymongo~=4.18`, `motor~=3.7`, `neo4j~=6.3`, `langgraph~=1.2`, `langchain-core~=1.6`, `google-genai~=2.22`, `pandas~=2.2` (sandbox has 2.2.3; 3.0 is out but 2.2 avoids the copy-on-write/string-dtype changes), `numpy>=2.0`, `pyarrow~=25.0`, `scikit-learn~=1.6`, `xgboost~=3.4`, `shap~=0.52`, `joblib`, `matplotlib`, `httpx~=0.28`, `sse-starlette~=3.4`, `python-jose[cryptography]`, `passlib[bcrypt]`, `reportlab~=5.0`, `mitreattack-python~=6.2` (or plain STIX JSON download), `networkx` (in-memory graph store), `python-ulid`, `pyyaml`, `tqdm`. Dev: `pytest`, `pytest-asyncio`, `mongomock`, `respx`, `ruff`.

**Frontend (`package.json`):** `react@19`, `react-dom@19`, `react-router-dom@7`, `axios@1`, `cytoscape@3`, `cytoscape-fcose`, `recharts@3`, `vite@8`, `@vitejs/plugin-react`.

**Infrastructure:** MongoDB 7/8 (Docker image or tarball), Neo4j 5.x Community (needs Java 17) or Neo4j 2025.x (Java 21); Neo4j Aura Free is a zero-install alternative.

---

## 15. Environment variables (`.env.example`)

```
# LLM
GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash          # verified at startup via models.list(); never hard-coded

# Threat intelligence (optional; system degrades gracefully when empty)
VIRUSTOTAL_API_KEY=
OTX_API_KEY=

# Databases
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=siem_kg
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=

# Investigation safeguards
MAX_INVESTIGATION_STEPS=12
MAX_EVENTS_PER_QUERY=500
MAX_TIME_WINDOW_SECONDS=86400
MAX_GRAPH_NODES=300
MAX_LLM_CALLS_PER_INVESTIGATION=20
MAX_TI_LOOKUPS_PER_INVESTIGATION=10
INVESTIGATION_TIMEOUT_SECONDS=300
INVESTIGATION_POLICY=llm               # llm | heuristic  (heuristic used automatically if no key)

# Data / ML
DATASET_DIR=./data/raw
PROCESSED_DIR=./data/processed
ARTIFACTS_DIR=./ml/artifacts
SUBSET_MAX_PER_CLASS=100000
RANDOM_SEED=42

# App
API_HOST=0.0.0.0
API_PORT=8000
FRONTEND_ORIGIN=http://localhost:5173
JWT_SECRET=change-me
DEMO_ANALYST_USERNAME=analyst
DEMO_ANALYST_PASSWORD=change-me
LOG_LEVEL=INFO
```

`.env` is git-ignored; React receives nothing but the relative API base.

---

## 16. Testing strategy

| Level | Scope | Tooling |
|---|---|---|
| Unit | label mapping, chunked inspector (fixture CSV with NaN/inf/duplicates/malformed rows), preprocessing determinism, severity rules, requirement predicates, candidate generation, sufficiency scoring, safeguards, derivation rules (in-memory graph store), grounding validator, TI normalisers (recorded fixtures), MITRE mapping | `pytest`, `mongomock`, `respx` |
| Integration | tools against a real/temporary MongoDB; Neo4j store against a live instance (skipped when unavailable); LangGraph run with `policy=heuristic` and stubbed LLM; API routes with `httpx.AsyncClient` | `pytest -m integration` |
| Contract | every LangGraph node reads/writes only its declared keys; every tool enforces limits; ground truth never appears in any tool/API payload (recursive key scan) | custom assertions |
| LLM | offline: fixed fake-LLM responses (valid choice, invalid action_id, malformed JSON → fallback); online (optional, key present): schema validity, grounding check pass rate on 5 scenarios | `pytest -m llm` |
| E2E | seed demo DB → create investigation → SSE stream → report → PDF; frontend smoke via Vite build + route render checks | scripted |
| Reproducibility | two runs with the same seed give identical subset hashes, metrics (RF/XGB deterministic settings), and identical heuristic-mode investigation traces | harness |

---

## 17. Research evaluation methodology

- **A. Detection:** accuracy, macro/weighted P/R/F1, per-class table, confusion matrices (RF vs XGB), inference latency; capped-subset vs. full-class-size ablation on one class to quantify the sampling effect.
- **B. Behavioral profiling:** top-k feature sets per class from four methods; inter-method agreement (RBO@10); feature-reduction curves (macro-F1 vs k); profile separability (mean |z| of top features vs benign).
- **C. Investigation:** completion rate, steps, evidence items, events retrieved, DB queries, LLM calls, TI lookups, wall-clock latency, related-alert discovery; distributions per attack category.
- **D. Knowledge graph:** nodes, edges by type, construction time, subgraph retrieval latency, evidence coverage (fraction of edges with ≥1 evidence id = must be 100 %), relevant-relationship precision/recall vs the scenario ground truth.
- **E. Adaptive vs baseline (critical):** identical alert set (≥ 30 alerts across categories, ≥ 10 multi-stage scenarios), three arms — *fixed* (3 predefined queries), *heuristic adaptive*, *LLM adaptive*. Metrics: time, DB queries, events retrieved, **relevant evidence discovered** (records belonging to the alert's scenario ÷ total scenario records = recall; ÷ retrieved = precision), **attack-chain completeness** (stages recovered ÷ ground-truth stages; ordering accuracy), false stage rate, report quality (rubric). Paired comparison with bootstrap CIs; seeds and configs stored in `evaluation_runs`.
- **F. LLM:** automatic grounding rate (claims with resolvable evidence_ids), hallucination rate (claims whose entities/numbers do not appear in the structured input — checked by the validator), narrative completeness (rubric over the 15 sections), readability (analyst rating form, Flesch score as a proxy); reported per model version and prompt version.

Every table in the paper is regenerated by `python -m evaluation.harness --run <config>` so the results are reproducible.

---

## 18. Risks, bottlenecks, and solutions

| # | Risk / bottleneck | Impact | Mitigation |
|---|---|---|---|
| 1 | **Dataset not yet available in the environment** | Phase 1 blocked | User uploads or mounts files into `data/raw/`; if the full 13 GB is impractical here, a subset of `part-*.csv` files is acceptable *for development* as long as it covers all in-scope labels — inspection will report exactly which files were used. |
| 2 | **No IPs/timestamps in public CSV** (to be verified) | Graph would be empty | Scenario Contextualiser with explicit provenance (Section 2.3, Decision D2). |
| 3 | Sandbox resources (2 vCPU / 1.9 GiB) | Full-data training infeasible | Streaming inspection; capped stratified subset; `hist` XGBoost; float32; SHAP on samples; heavy runs can be repeated on the user's machine with larger caps (config only). |
| 4 | No Docker in the sandbox; Neo4j needs Java 17/21 | Demo infra | Provide `docker-compose.yml` for the user's machine; in the sandbox run MongoDB tarball + Neo4j with a downloaded Temurin JDK, or connect to Neo4j Aura Free / MongoDB Atlas via `.env`; `InMemoryGraphStore` keeps tests/evaluation independent of Neo4j. |
| 5 | Gemini model churn / quota | Runtime failures | `GEMINI_MODEL` env + startup availability check + heuristic policy fallback + retry/backoff + per-investigation LLM budget. |
| 6 | VT/OTX keys absent or rate-limited (VT free tier: 4 req/min) | TI gaps | Async + cache + rate limiter; `status: not_configured/unavailable`; documentation-range IPs are short-circuited as `private_address` so TI is exercised only on genuine public indicators (Decision D3). |
| 7 | LLM hallucination | Research validity | Candidate-restricted action choice; grounding validator that rejects claims without evidence ids or with entities absent from input; "Insufficient evidence" enforced phrasing; raw vs AI-interpretation separation. |
| 8 | Adaptive loop degenerating into a fixed order | Undermines contribution | Requirements depend on hypothesis/entities; novelty discounting; evaluation logs action sequences and reports sequence diversity across incidents. |
| 9 | MongoDB query cost on large collections | Latency | Compound indexes, `MAX_EVENTS_PER_QUERY`, aggregates before row pulls, projection of `features` only when needed. |
| 10 | Neo4j growth across many investigations | Slow UI | Per-investigation `investigation_id` on relationships, `MAX_GRAPH_NODES`, subgraph queries with limits, cleanup script. |
| 11 | Ground-truth leakage into agent reasoning | Invalid evaluation | `ground_truth` sub-document projected out at the tool layer + contract test scanning all payloads. |
| 12 | Scope creep (11 pages, 8 agents, evaluation) | Schedule | Strict phase gates; frontend built after the API is stable; PDF export via ReportLab kept simple. |

---

## 19. Decisions that must be confirmed before implementation

| ID | Decision | Recommended default | Alternatives |
|---|---|---|---|
| **D1** | **Dataset provisioning** — how do the CICIoT2023 files reach the environment? | Upload/mount the `part-*.csv` files into `data/raw/` (a subset of files is acceptable for development if all in-scope labels are covered; the inspector reports coverage) | Provide a download URL/credentials; or run Phases 1–6 on your own machine with the provided scripts and upload only the produced `processed/` artifacts |
| **D2** | **Entity/time context** if the CSVs have no IPs/timestamps | Scenario Contextualiser with explicit `provenance = synthesized` banners (Section 2.3) | Use raw pcaps (not provided, very heavy); restrict the prototype to a graph without IP entities (much weaker demo) |
| **D3** | **Public-IP policy for threat intelligence** | Use documentation ranges (203.0.113.0/24 etc.) for synthesized attackers → TI returns `private_address`/no-data for them, plus a small opt-in list of well-known public indicators (e.g., known scanner/sinkhole IPs) for demonstrating live VT/OTX enrichment | Run TI only on user-provided indicators via the TI page |
| **D4** | **Per-class cap for the experimental subset** | 100 000 rows/class (minority classes in full), seed 42 | 50 000 (faster in the sandbox) or 250 000+ (your machine) |
| **D5** | **Browser Hijacking** | Excluded from initial implementation (optional per brief) | Include as a 24th class |
| **D6** | **Gemini model** | `GEMINI_MODEL=gemini-2.5-flash` | `gemini-3.5-flash` / `gemini-2.5-pro` (cost/latency trade-off); you must supply the API key |
| **D7** | **Infrastructure for the demo** | Docker Compose (Mongo + Neo4j + backend + frontend) on your machine; in this sandbox: MongoDB tarball + Neo4j with downloaded JDK 21 | Neo4j Aura Free + MongoDB Atlas (cloud, zero install) |
| **D8** | **Investigation policy arms for evaluation** | fixed baseline vs heuristic adaptive vs LLM adaptive | fixed vs LLM only |
| **D9** | **Login** | Demo JWT login with env-configured analyst account | No login (landing only) |
| **D10** | **Report export** | HTML report + PDF via ReportLab | HTML/print-to-PDF only |

Once D1 (at minimum) is answered, **Phase 1 — Dataset inspection** begins: a streaming inspector that reports files, sizes, rows, columns, dtypes, missing/inf values, duplicates, unique labels, class distribution and in-scope coverage — from the actual files only.
