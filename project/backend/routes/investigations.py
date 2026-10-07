"""Investigations (create/start/stream/inspect), knowledge graph, reports and evaluation."""
from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from backend.deps import Container, current_user, get_container
from backend.routes.common import jsonable, page_args
from backend.services.reports import report_to_markdown, report_to_pdf
from backend.utils.ids import new_id

log = logging.getLogger(__name__)
router = APIRouter()


class CreateInvestigation(BaseModel):
    alert_id: str
    mode: str = "adaptive"          # adaptive | baseline
    policy: Optional[str] = None    # llm | heuristic (adaptive only)
    autostart: bool = True


# ------------------------------------------------------------------ investigations
@router.get("/investigations")
def list_investigations(page: int = 1, page_size: int = 50, status: Optional[str] = None, mode: Optional[str] = None, alert_id: Optional[str] = None,
                        c: Container = Depends(get_container), user: dict = Depends(current_user)):
    skip, limit = page_args(page, page_size)
    q = {k: v for k, v in (("status", status), ("mode", mode), ("alert_id", alert_id)) if v}
    coll = c.store["investigations"]
    total = coll.count_documents(q)
    rows = list(coll.find(q, {"state": 0, "steps": 0, "traceback": 0}).sort([("created_at", -1)]).skip(skip).limit(limit))
    return jsonable({"page": page, "page_size": limit, "total": total, "items": rows})


@router.post("/investigations", status_code=201)
def create_investigation(body: CreateInvestigation, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    if body.mode not in ("adaptive", "baseline"):
        raise HTTPException(400, "mode must be adaptive or baseline")
    if body.policy and body.policy not in ("llm", "heuristic"):
        raise HTTPException(400, "policy must be llm or heuristic")
    try:
        doc = c.runner.create(body.alert_id, mode=body.mode, policy=body.policy)
    except KeyError:
        raise HTTPException(404, "alert not found")
    c.store["investigations"].update_one({"_id": doc["_id"]}, {"$set": {"created_by": user.get("username")}})
    if body.autostart:
        doc = c.runner.start(doc["_id"])
    return jsonable({k: v for k, v in doc.items() if k not in ("state", "steps")})


@router.post("/investigations/{inv_id}/start")
def start_investigation(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    try:
        doc = c.runner.start(inv_id)
    except KeyError:
        raise HTTPException(404, "investigation not found")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    return jsonable({k: v for k, v in doc.items() if k not in ("state", "steps")})


@router.post("/investigations/{inv_id}/stop")
def stop_investigation(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    c.runner.stop(inv_id)
    return {"investigation_id": inv_id, "stop_requested": True}


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: str, include_state: bool = True, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    proj = None if include_state else {"state": 0}
    d = c.store["investigations"].find_one({"_id": inv_id}, proj)
    if not d:
        raise HTTPException(404, "investigation not found")
    d.pop("traceback", None)
    return jsonable(d)


@router.get("/investigations/{inv_id}/steps")
def investigation_steps(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["investigations"].find_one({"_id": inv_id}, {"steps": 1, "status": 1})
    if not d:
        raise HTTPException(404, "investigation not found")
    return jsonable({"investigation_id": inv_id, "status": d["status"], "steps": d.get("steps", [])})


@router.get("/investigations/{inv_id}/evidence")
def investigation_evidence(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["investigations"].find_one({"_id": inv_id}, {"state.evidence": 1, "state.tool_history": 1, "state.missing_evidence": 1, "state.candidate_actions": 1})
    if not d:
        raise HTTPException(404, "investigation not found")
    st = d.get("state") or {}
    return jsonable({"investigation_id": inv_id, "evidence": st.get("evidence", []), "tool_history": st.get("tool_history", []),
                     "missing_evidence": st.get("missing_evidence", []), "candidate_actions": st.get("candidate_actions", [])})


@router.get("/investigations/{inv_id}/evidence/{evidence_id}/records")
def evidence_records(inv_id: str, evidence_id: str, limit: int = 100, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """The actual records behind an evidence item (paged from the repository, ground truth stripped)."""
    d = c.store["investigations"].find_one({"_id": inv_id}, {"state.evidence": 1})
    if not d:
        raise HTTPException(404, "investigation not found")
    item = next((e for e in (d.get("state") or {}).get("evidence", []) if e["evidence_id"] == evidence_id), None)
    if not item:
        raise HTTPException(404, "evidence item not found")
    ids = item.get("record_ids", [])[:limit]
    events = c.repo.get_events_by_ids([i for i in ids if str(i).startswith("evt_")])
    alerts = list(c.store["alerts"].find({"_id": {"$in": [i for i in ids if str(i).startswith("alr_")]}}))
    return jsonable({"evidence": item, "events": events, "alerts": alerts})


@router.get("/investigations/{inv_id}/stream")
async def stream_investigation(inv_id: str, request: Request, c: Container = Depends(get_container)):
    """Server-Sent Events: replay of persisted steps, then live agent actions until done."""
    doc = c.store["investigations"].find_one({"_id": inv_id}, {"steps": 1, "status": 1})
    if not doc:
        raise HTTPException(404, "investigation not found")
    q = c.runner.bus.subscribe(inv_id)

    async def gen():
        try:
            for a in doc.get("steps", []):
                yield {"event": "agent_action", "data": json.dumps(jsonable({"type": "agent_action", "investigation_id": inv_id, "action": a, "replay": True}))}
            if doc["status"] in ("completed", "failed", "stopped"):
                yield {"event": "done", "data": json.dumps({"type": "done", "investigation_id": inv_id, "status": doc["status"]})}
                return
            loop = asyncio.get_event_loop()
            while True:
                if await request.is_disconnected():
                    return
                try:
                    ev = await loop.run_in_executor(None, q.get, True, 1.0)
                except queue.Empty:
                    yield {"event": "ping", "data": "{}"}
                    continue
                yield {"event": ev["type"], "data": json.dumps(jsonable(ev))}
                if ev["type"] == "done":
                    return
        finally:
            c.runner.bus.unsubscribe(inv_id, q)

    return EventSourceResponse(gen())


# ------------------------------------------------------------------ graph
@router.get("/graph/{inv_id}")
def get_graph(inv_id: str, types: Optional[str] = None, start: Optional[str] = None, end: Optional[str] = None, limit: int = 1000,
              c: Container = Depends(get_container), user: dict = Depends(current_user)):
    t = [x for x in types.split(",") if x] if types else None
    sg = c.graph.get_subgraph(inv_id, types=t, start=start, end=end, limit=min(limit, 3000))
    return jsonable({"investigation_id": inv_id, "backend": c.graph.backend, **sg, "summary": c.graph.summary(inv_id)})


@router.get("/graph/{inv_id}/node")
def get_node(inv_id: str, key: str, records: int = 50, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Node-click endpoint: node properties, relationships, and the evidence records that support it."""
    info = c.graph.node_evidence(inv_id, key)
    if not info.get("found"):
        raise HTTPException(404, "node not found in this investigation")
    ids = info.get("evidence_ids", [])
    evt_ids = [i for i in ids if str(i).startswith("evt_")][:records]
    evd_ids = [i for i in ids if str(i).startswith("evd_")]
    events = c.repo.get_events_by_ids(evt_ids) if evt_ids else []
    evidence_items = []
    if evd_ids:
        d = c.store["investigations"].find_one({"_id": inv_id}, {"state.evidence": 1})
        evidence_items = [e for e in ((d or {}).get("state") or {}).get("evidence", []) if e["evidence_id"] in evd_ids]
    return jsonable({**info, "events": events, "evidence_items": evidence_items,
                     "note": "Every node/edge lists the record ids it was derived from; events are fetched live from the repository (ground truth never included)."})


@router.get("/graph/{inv_id}/related")
def related(inv_id: str, key: str, depth: int = 1, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    return jsonable(c.graph.related_nodes(key, inv_id, min(depth, 3)))


# ------------------------------------------------------------------ reports
@router.get("/reports")
def list_reports(page: int = 1, page_size: int = 50, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    skip, limit = page_args(page, page_size)
    coll = c.store["reports"]
    rows = list(coll.find({}, {"sections": 0, "claims": 0}).sort([("generated_at", -1)]).skip(skip).limit(limit))
    return jsonable({"page": page, "page_size": limit, "total": coll.count_documents({}), "items": rows})


def _report(c: Container, inv_id: str) -> dict:
    r = c.store["reports"].find_one({"investigation_id": inv_id})
    if not r:
        d = c.store["investigations"].find_one({"_id": inv_id}, {"state.final_report": 1, "status": 1})
        if not d:
            raise HTTPException(404, "investigation not found")
        r = (d.get("state") or {}).get("final_report")
        if not r:
            raise HTTPException(404, f"no report yet (investigation status: {d['status']})")
    return r


@router.get("/reports/{inv_id}")
def get_report(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    return jsonable(_report(c, inv_id))


@router.get("/reports/{inv_id}/markdown", response_class=PlainTextResponse)
def report_markdown(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    return report_to_markdown(jsonable(_report(c, inv_id)))


@router.get("/reports/{inv_id}/pdf")
def report_pdf(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    rep = jsonable(_report(c, inv_id))
    path = Path(c.settings.reports_dir) / "pdf" / f"{inv_id}.pdf"
    report_to_pdf(rep, path)
    return FileResponse(str(path), media_type="application/pdf", filename=f"{inv_id}.pdf")


# ------------------------------------------------------------------ evaluation
class EvalBody(BaseModel):
    alert_ids: Optional[list[str]] = None
    n_alerts: int = 6
    policies: Optional[list[str]] = None
    name: str = ""


_eval_jobs: dict = {}


@router.post("/evaluation/run", status_code=202)
def run_evaluation(body: EvalBody, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    job_id = new_id("job")
    _eval_jobs[job_id] = {"status": "running", "run_id": None}

    def work():
        try:
            doc = c.evaluator.run_comparison(alert_ids=body.alert_ids, n_alerts=min(body.n_alerts, 30), policies=body.policies, name=body.name)
            _eval_jobs[job_id] = {"status": "completed", "run_id": doc["_id"]}
        except Exception as exc:
            log.exception("evaluation failed")
            _eval_jobs[job_id] = {"status": "failed", "error": str(exc)}

    threading.Thread(target=work, daemon=True, name=f"eval-{job_id}").start()
    return {"job_id": job_id, "status": "running"}


@router.get("/evaluation/jobs/{job_id}")
def eval_job(job_id: str):
    if job_id not in _eval_jobs:
        raise HTTPException(404, "job not found")
    return _eval_jobs[job_id]


@router.get("/evaluation/runs")
def eval_runs(c: Container = Depends(get_container), user: dict = Depends(current_user)):
    rows = list(c.store["evaluation_runs"].find({}, {"rows": 0}).sort([("created_at", -1)]).limit(50))
    return jsonable(rows)


@router.get("/evaluation/runs/{run_id}")
def eval_run(run_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["evaluation_runs"].find_one({"_id": run_id})
    if not d:
        raise HTTPException(404, "run not found")
    return jsonable(d)


@router.get("/evaluation/score/{inv_id}")
def score_investigation(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    try:
        return jsonable(c.evaluator.score_investigation(inv_id))
    except KeyError:
        raise HTTPException(404, "investigation not found or not finished")


@router.get("/evaluation/grounding/{inv_id}")
def grounding(inv_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Claim-level traceability: every claim → evidence ids → records exist in the repository."""
    rep = _report(c, inv_id)
    inv = c.store["investigations"].find_one({"_id": inv_id}, {"state.evidence": 1})
    ev_ids = {e["evidence_id"] for e in ((inv or {}).get("state") or {}).get("evidence", [])}
    rows = []
    for cl in rep.get("claims", []):
        ids = cl.get("evidence_ids", [])
        evt = [i for i in ids if str(i).startswith("evt_")]
        found_evt = {d["_id"] for d in c.store["security_events"].find({"_id": {"$in": evt}}, {"_id": 1})} if evt else set()
        found_alr = {d["_id"] for d in c.store["alerts"].find({"_id": {"$in": [i for i in ids if str(i).startswith("alr_")]}}, {"_id": 1})}
        resolved = [i for i in ids if i in ev_ids or i in found_evt or i in found_alr]
        rows.append({"claim": cl["text"], "evidence_ids": ids, "resolved": len(resolved), "unresolved": [i for i in ids if i not in resolved], "validated": cl.get("validated")})
    narr = (rep.get("sections") or {}).get("13_ai_attack_narrative") or {}
    return jsonable({"investigation_id": inv_id, "claims": rows, "claims_total": len(rows), "claims_fully_resolved": sum(1 for r in rows if not r["unresolved"] and r["evidence_ids"]),
                     "narrative_validation": narr.get("grounding_validation"), "narrative_generated_by": narr.get("generated_by")})
