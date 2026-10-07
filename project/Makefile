.PHONY: install api ui build test pipeline inspect smoke ingest-smoke eval mitre

install:            ## python + node dependencies
	pip install -r requirements.txt
	cd frontend && npm install --no-audit --no-fund

api:                ## run the backend (serves frontend/dist when built)
	python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

ui:                 ## Vite dev server with /api proxy
	cd frontend && npm run dev

build:              ## production React build -> frontend/dist
	cd frontend && npm run build

test:               ## unit + contract tests (no external services)
	python -m pytest tests/unit -q

pipeline:           ## offline pipeline: inspect -> clean -> subset -> train -> profiles -> events -> alerts
	python -m ml.pipeline run

inspect:            ## dataset inspection only (needs part-*.csv in DATASET_DIR)
	python -m ml.pipeline inspect

smoke:              ## one adaptive + one baseline investigation from the CLI
	python scripts/smoke_investigation.py && python scripts/smoke_investigation.py --mode baseline

ingest-smoke:        ## validate the post-inference live ingestion bridge against a running API
	python scripts/ingest_smoke.py

eval:               ## paired adaptive-vs-baseline comparison
	python scripts/run_evaluation.py --n 10

mitre:              ## download the public ATT&CK enterprise STIX bundle (optional)
	python -m backend.services.mitre download
