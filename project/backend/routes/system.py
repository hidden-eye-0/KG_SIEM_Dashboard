"""Health, configuration, dataset, models, behaviour profiles, auth."""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.deps import Container, create_token, current_user, get_container
from backend.routes.common import jsonable
from backend.services.mitre import CURATED
from ml.pipeline import detect_mode

log = logging.getLogger(__name__)
router = APIRouter()


# ------------------------------------------------------------------ health / config
@router.get("/health")
def health(c: Container = Depends(get_container)):
    mongo = c.store.ping()
    graph = c.graph.ping() if hasattr(c.graph, "ping") else {"status": "ok", "backend": c.graph.backend}
    return {
        "status": "ok" if mongo.get("status") == "ok" else "degraded",
        "started_at": c.started_at.isoformat(),
        "mongo": mongo, "graph": graph,
        "gemini": c.llm.availability,
        "mitre": {"bundle_loaded": c.mitre.bundle_loaded, "curated_attack_types": len(CURATED)},
        "threat_intel": {"virustotal": bool(c.settings.virustotal_api_key), "otx": bool(c.settings.otx_api_key)},
        "pipeline_mode": detect_mode(c.settings),
        "seed": c.seed_status,
        "counts": c.store.counts(),
    }


@router.get("/config")
def config(c: Container = Depends(get_container)):
    d = c.settings.public_dict()
    d["pipeline_mode"] = detect_mode(c.settings)
    d["dataset_placeholder"] = d["pipeline_mode"] == "demo"
    d["sufficiency_threshold"] = c.settings.sufficiency_threshold
    return d


# ------------------------------------------------------------------ auth
class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginBody, c: Container = Depends(get_container)):
    s = c.settings
    if body.username != s.demo_analyst_username or body.password != s.demo_analyst_password:
        raise HTTPException(401, "invalid credentials")
    return {"access_token": create_token(s, body.username), "token_type": "bearer", "username": body.username, "role": "analyst"}


@router.get("/auth/me")
def me(user: dict = Depends(current_user)):
    return user


# ------------------------------------------------------------------ dataset
@router.get("/dataset/status")
def dataset_status(c: Container = Depends(get_container)):
    mode = detect_mode(c.settings)
    stats = c.store["dataset_stats"].find_one({"_id": "latest"}) or {}
    files = []
    d = Path(c.settings.dataset_dir)
    if d.exists():
        files = sorted(p.name for p in d.glob("*.csv"))[:200]
    return jsonable({
        "mode": mode, "dataset_dir": str(d), "csv_files": files, "file_count": len(files),
        "placeholder_note": None if mode == "dataset" else "DATASET_DIR contains no CSV files. All events/alerts/models come from synthetic demo flows (data_source='synthetic_demo'). Copy CICIoT2023 part-*.csv files into the directory and POST /api/dataset/reseed.",
        "inspection": stats.get("inspection"), "preprocess_report": stats.get("preprocess_report"), "generated_at": stats.get("generated_at"),
    })


@router.get("/dataset/inspection")
def dataset_inspection(c: Container = Depends(get_container)):
    p = Path(c.settings.reports_dir) / "dataset_inspection.json"
    if not p.exists():
        stats = c.store["dataset_stats"].find_one({"_id": "latest"}) or {}
        if stats.get("inspection"):
            return jsonable(stats["inspection"])
        raise HTTPException(404, "no inspection report — dataset placeholder mode (no CSV files) or pipeline not run")
    return json.loads(p.read_text())


@router.get("/dataset/scenarios")
def scenarios(c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Scenario metadata WITHOUT stage ground truth (ground truth is evaluation-only)."""
    out = []
    for s in c.store["scenarios"].find({}):
        stages = s.get("stages") or []
        out.append({"_id": s["_id"], "name": s.get("name"), "sources": s.get("sources"), "targets": s.get("targets"), "event_count": s.get("event_count"),
                    "stage_count": len(stages), "first_seen": min((st["first_seen"] for st in stages), default=None), "last_seen": max((st["last_seen"] for st in stages), default=None),
                    "note": "stage labels are hidden (ground truth is used only by the evaluation harness)"})
    return jsonable(out)


def _reseed(c: Container, fast: bool) -> None:
    from ml.pipeline import run_all

    c.seed_status = {"status": "running", "fast": fast}
    try:
        for coll in ("security_events", "alerts", "investigations", "reports", "scenarios", "evaluation_runs"):
            c.store[coll].delete_many({})
        summary = run_all(c.settings, c.store, fast=fast)
        c.seed_status = {"status": "completed", **jsonable(summary)}
    except Exception as exc:  # pragma: no cover
        log.exception("reseed failed")
        c.seed_status = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}


@router.post("/dataset/reseed")
def reseed(fast: bool = True, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Re-run inspection → preprocessing → training → profiles → contextualisation → alerts (background)."""
    if c.seed_status.get("status") == "running":
        return {"status": "already_running"}
    threading.Thread(target=_reseed, args=(c, fast), daemon=True, name="reseed").start()
    return {"status": "started", "fast": fast}


# ------------------------------------------------------------------ models / profiles
@router.get("/models")
def models(c: Container = Depends(get_container)):
    docs = list(c.store["models"].find({}).sort([("created_at", -1)]))
    out = []
    for d in docs:
        out.append({k: d.get(k) for k in ("_id", "version", "created_at", "data_source", "primary_model", "selection_rule", "n_train", "n_val", "n_test", "seed", "classes")}
                   | {"models": {m: {k: v for k, v in r.items() if k in ("train_seconds", "inference_seconds_test", "inference_us_per_row", "params")}
                                 | {"validation": {k: v for k, v in r["validation"].items() if k not in ("per_class", "confusion_matrix")},
                                    "test": {k: v for k, v in r["test"].items() if k not in ("per_class", "confusion_matrix")}}
                                 for m, r in d.get("models", {}).items()}})
    return jsonable(out)


@router.get("/models/{version}")
def model_detail(version: str, c: Container = Depends(get_container)):
    d = c.store["models"].find_one({"_id": version}) if version != "latest" else next(iter(c.store["models"].find({}).sort([("created_at", -1)]).limit(1)), None)
    if not d:
        raise HTTPException(404, "model version not found")
    return jsonable(d)


@router.get("/profiles")
def profiles(c: Container = Depends(get_container)):
    docs = list(c.store["behavior_profiles"].find({"kind": {"$ne": "global"}}))
    return jsonable([{k: d.get(k) for k in ("_id", "raw_label", "attack_type", "category", "model_version", "data_source", "n_samples_train", "top_features", "dominant_protocols", "profile_statement", "feature_group_scores")} for d in docs])


@router.get("/profiles/global")
def global_profile(c: Container = Depends(get_container)):
    d = c.store["behavior_profiles"].find_one({"_id": "bp__global"})
    if not d:
        raise HTTPException(404, "no global profile (pipeline not run)")
    return jsonable(d)


@router.get("/profiles/{profile_id}")
def profile_detail(profile_id: str, c: Container = Depends(get_container)):
    d = c.store["behavior_profiles"].find_one({"_id": profile_id}) or c.store["behavior_profiles"].find_one({"attack_type": profile_id})
    if not d:
        raise HTTPException(404, "profile not found")
    return jsonable(d)
