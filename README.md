# Adaptive Knowledge-Graph SIEM

This repository contains the active **Adaptive Knowledge-Graph-Based SIEM Investigation Framework** under [`project/`](project/).

The system is designed to take a security alert and reconstruct what happened using evidence rather than relying on an LLM-only summary:

```
Security events
    ↓
ML detection / model integration
    ↓
Alert aggregation
    ↓
Adaptive investigation
    ↓
Evidence retrieval
    ↓
Knowledge graph
    ↓
MITRE ATT&CK + passive threat intelligence
    ↓
Attack reconstruction
    ↓
Evidence-grounded attack story
    ↓
Report
```

## Current implementation

The `project/` tree contains:

- FastAPI backend with REST + SSE
- LangGraph investigation workflow
- adaptive and fixed-baseline investigation modes
- deterministic NetworkX / Neo4j knowledge graph
- evidence-traceable reports and Markdown/PDF export
- passive VirusTotal / OTX integration
- curated MITRE ATT&CK mapping with optional STIX verification
- React SOC dashboard
- JWT authentication path
- dataset inspection / preprocessing / sample pipeline
- evaluation harness
- controlled post-inference `POST /api/ingest` bridge
- Docker Compose and CI

## Important model boundary

The model currently exercised by the SIEM repository is a **small development/sample model**. The production-quality trained detector is maintained separately and is intentionally integrated only after the investigation, graph, intelligence, reporting and deployment layers are complete.

The ingestion contract is therefore model-agnostic: the final detector can post canonical predictions to:

```
POST /api/ingest
```

See [`project/README.md`](project/README.md) for the detailed architecture and runbook.

## Quick start

```bash
cd project
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
cd project/frontend
npm install
npm run dev
```

Backend API documentation:

```
http://localhost:8000/docs
```

## Development checks

From `project/`:

```bash
python -m pytest tests/unit -q
npm --prefix frontend ci
npm --prefix frontend run build
python scripts/ingest_smoke.py
```

## Repository layout

```
project/
├── backend/       FastAPI, LangGraph agents, tools and services
├── frontend/      React SOC dashboard
├── ml/            preprocessing, sample training and explainability
├── scripts/       smoke/evaluation utilities
├── tests/         backend contract tests
├── docs/          architecture and build status
└── data/          runtime data, scenarios and reports
```

## Security principles

Secrets stay in `.env` and are never sent to the frontend. Investigation tools strip hidden ground-truth fields before agent access. External threat intelligence is passive and private/documentation IPs are not sent to providers. LLM output is treated as interpretation and is validated against known evidence before being accepted as the investigation narrative.

## Status

The active completion branch is `project-completion`. See [`project/docs/BUILD_STATUS.md`](project/docs/BUILD_STATUS.md) for the current implementation status and remaining final-model/deployment steps.
