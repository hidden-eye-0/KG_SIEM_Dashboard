"""FastAPI entry point.

    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

Startup:
  1. connect Mongo (Atlas via MONGODB_URI or in-process mongomock) and graph store (Aura via NEO4J_* or NetworkX)
  2. verify GEMINI_MODEL with models.list() (non-fatal)
  3. if the store is empty and AUTO_SEED_DEMO=true → run the offline pipeline in the background
     (dataset mode when DATASET_DIR has CSVs, otherwise synthetic demo placeholder)
  4. serve the API under /api and, when frontend/dist exists, the built React app
"""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.deps import build_container, get_container
from backend.routes import data, investigations, system
from backend.utils.logging import setup_logging

log = logging.getLogger("api")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def _seed_if_empty(c) -> None:
    from ml.pipeline import detect_mode, run_all

    try:
        if c.store["security_events"].estimated_document_count() > 0:
            c.seed_status = {"status": "present", "note": "store already populated"}
            return
        if not c.settings.auto_seed_demo:
            c.seed_status = {"status": "skipped", "note": "AUTO_SEED_DEMO=false and store empty — run `python -m ml.pipeline run`"}
            return
        mode = detect_mode(c.settings)
        c.seed_status = {"status": "running", "mode": mode}
        summary = run_all(c.settings, c.store, fast=(mode == "demo"))
        c.seed_status = {"status": "completed", **{k: (str(v) if not isinstance(v, (int, float, str, dict, list, type(None))) else v) for k, v in summary.items()}}
    except Exception as exc: 
        log.exception("auto-seed failed")
        c.seed_status = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.log_level)
    c = build_container(settings)
    log.info("store=%s graph=%s policy=%s", c.store.backend, c.graph.backend, settings.effective_policy)
    threading.Thread(target=c.llm.verify_model, daemon=True, name="gemini-verify").start()
    threading.Thread(target=_seed_if_empty, args=(c,), daemon=True, name="auto-seed").start()
    yield


app = FastAPI(title="Adaptive Knowledge-Graph SIEM Investigation Framework", version="1.0.0", lifespan=lifespan,
              description="Research prototype: ML detection → alerts → LangGraph adaptive investigation → knowledge graph → evidence-backed attack story.")

_settings = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=_settings.cors_origins(), allow_origin_regex=r"https?://.*", allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

app.include_router(system.router, prefix="/api", tags=["system"])
app.include_router(data.router, prefix="/api", tags=["data"])
app.include_router(investigations.router, prefix="/api", tags=["investigations"])


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


@app.get("/api")
def api_root():
    return {"name": app.title, "version": app.version, "docs": "/docs", "health": "/api/health"}


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(FRONTEND_DIST / "index.html"))
else:
    @app.get("/", include_in_schema=False)
    def root():
        return {"message": "API running. Build the frontend (cd frontend && npm run build) or run the Vite dev server on :5173.", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=_settings.api_host, port=_settings.api_port, reload=False)
