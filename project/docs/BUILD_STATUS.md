# Build status — current system (2026-10-07)

| Area | Status | Current evidence |
|---|---|---|
| Dataset inspection | ✅ Working | Real uploaded CICIoT2023-derived CSV inspected locally |
| Demo/sample ML pipeline | ✅ Working | Small sample dataset used for SIEM integration testing; final trained model will be integrated later |
| Event generation | ✅ Working | 4,590 events generated in current dataset-mode seed |
| Alert generation | ✅ Working | 65 alerts generated |
| Investigation runtime | ✅ Implemented | FastAPI create/start/stop/stream/evidence/report endpoints + LangGraph runner |
| Adaptive investigation | ✅ Implemented | State-dependent policy, evidence-gap loop and safeguards |
| Baseline investigation | ✅ Implemented | Fixed-policy comparison path |
| Knowledge graph | ✅ Implemented | NetworkX fallback + Neo4j integration path, evidence-linked nodes/edges |
| Threat intelligence | ✅ Implemented | Passive VT/OTX paths, gated and cached; providers optional |
| MITRE ATT&CK | ⚠️ Partial configuration | Curated mapping available; full STIX bundle not loaded in current environment |
| Gemini | ⚠️ Optional | Backend fallback works; current environment reports GEMINI_API_KEY not set |
| Reports | ✅ Implemented | 15-section report model + Markdown/PDF endpoints |
| Evaluation | ✅ Implemented | Adaptive-vs-baseline comparison harness and grounding metrics |
| React SOC dashboard | ✅ Implemented | Alerts, investigations, graph, attack story, TI, events, models, evaluation, settings |
| Authentication | ✅ Implemented | JWT path exists; production deployment should enable AUTH_REQUIRED |
| Persistence | ⚠️ Development fallback | Current run uses mongomock + NetworkX; persistent MongoDB/Neo4j remain deployment configuration |
| Live ingestion | ⚠️ Not finalised | Dataset seeding is working; live external-event ingestion is still a final integration task |
| Final trained model | ⏳ Intentionally deferred | Will be integrated from the separate model repository at the end |

## Current development run

The current SIEM run is intentionally **not the final ML model**. The small CICIoT2023-derived sample is being used to exercise the end-to-end product workflow while the production-quality trained model remains in a separate repository.

Latest reported runtime state:

- pipeline mode: `dataset`
- data source: `CICIoT2023`
- primary model in this development run: `xgboost`
- model version: `20261007T010231Z`
- test Macro-F1: `0.7477459096`
- events: `4590`
- alerts: `65`
- scenarios: `15`
- behavior profiles: `24`

**Interpretation:** these metrics are development/sample-run results and must not be presented as the final trained-model performance.

## Remaining completion work

The remaining work is primarily validation, deployment hardening and product integration rather than rebuilding the already-implemented investigation stack:

1. Exercise at least one real alert through adaptive investigation end-to-end.
2. Verify graph/evidence traceability from alert → evidence → graph → chain → report.
3. Run paired adaptive-vs-baseline evaluation and store a reproducible result.
4. Validate MITRE bundle loading and mapping.
5. Configure Gemini/TI providers for the final demo where credentials are available.
6. Validate persistent MongoDB + Neo4j deployment.
7. Enable and test authentication for production/demo deployment.
8. Add/validate controlled live ingestion if required by the final demonstration.
9. Run backend tests, frontend build and UI smoke after final changes.
10. Integrate the separate final trained model last and run a complete regression pass.