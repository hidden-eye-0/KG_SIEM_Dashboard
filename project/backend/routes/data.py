"""Security events, alerts and threat-intelligence endpoints (read paths + TI lookup)."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.deps import Container, current_user, get_container
from backend.routes.common import jsonable, page_args, parse_time
from backend.services.repository import strip_ground_truth
from backend.services.threat_intel import indicator_type

log = logging.getLogger(__name__)
router = APIRouter()


# ------------------------------------------------------------------ events
@router.get("/events")
def list_events(page: int = 1, page_size: int = 50, source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
                device_id: Optional[str] = None, attack_type: Optional[str] = None, category: Optional[str] = None,
                protocol: Optional[str] = None, start: Optional[str] = None, end: Optional[str] = None, sort: str = "-timestamp",
                c: Container = Depends(get_container), user: dict = Depends(current_user)):
    skip, limit = page_args(page, page_size)
    q: dict = {}
    for k, v in (("source_ip", source_ip), ("destination_ip", destination_ip), ("device_id", device_id), ("protocol", protocol)):
        if v:
            q[k] = v
    if attack_type:
        q["prediction.attack_type"] = attack_type
    if category:
        q["prediction.category"] = category
    s, e = parse_time(start, "start"), parse_time(end, "end")
    if s or e:
        q["timestamp"] = {k: v for k, v in (("$gte", s), ("$lte", e)) if v}
    direction = -1 if sort.startswith("-") else 1
    field = sort.lstrip("-") or "timestamp"
    coll = c.store["security_events"]
    total = coll.count_documents(q)
    rows = [strip_ground_truth(d) for d in coll.find(q).sort([(field, direction)]).skip(skip).limit(limit)]
    return jsonable({"page": page, "page_size": limit, "total": total, "items": rows})


@router.get("/events/summary")
def events_summary(c: Container = Depends(get_container), user: dict = Depends(current_user)):
    coll = c.store["security_events"]
    by_type = list(coll.aggregate([{"$group": {"_id": "$prediction.attack_type", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]))
    by_cat = list(coll.aggregate([{"$group": {"_id": "$prediction.category", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]))
    by_proto = list(coll.aggregate([{"$group": {"_id": "$protocol", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]))
    by_device = list(coll.aggregate([{"$group": {"_id": "$device_id", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 20}]))
    span = list(coll.aggregate([{"$group": {"_id": None, "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}}}]))
    src = coll.find_one({}, {"dataset": 1, "context.provenance": 1})
    return jsonable({"total": coll.estimated_document_count(), "by_attack_type": by_type, "by_category": by_cat, "by_protocol": by_proto, "by_device": by_device,
                     "time_span": span[0] if span else None, "data_source": ((src or {}).get("dataset") or {}).get("source"),
                     "provenance": ((src or {}).get("context") or {}).get("provenance")})


@router.get("/events/timeline")
def events_timeline(bucket_minutes: int = 5, start: Optional[str] = None, end: Optional[str] = None, source_ip: Optional[str] = None,
                    c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Counts per (time bucket, category) for the dashboard chart — computed in the DB, rows are never shipped."""
    q: dict = {}
    if source_ip:
        q["source_ip"] = source_ip
    s, e = parse_time(start, "start"), parse_time(end, "end")
    if s or e:
        q["timestamp"] = {k: v for k, v in (("$gte", s), ("$lte", e)) if v}
    ms = max(1, bucket_minutes) * 60 * 1000
    pipeline = [{"$match": q}] if q else []
    pipeline += [
        {"$group": {"_id": {"bucket": {"$subtract": [{"$toLong": "$timestamp"}, {"$mod": [{"$toLong": "$timestamp"}, ms]}]}, "category": "$prediction.category"}, "count": {"$sum": 1}}},
        {"$sort": {"_id.bucket": 1}}, {"$limit": 5000},
    ]
    try:
        rows = list(c.store["security_events"].aggregate(pipeline))
        out = [{"bucket_ms": r["_id"]["bucket"], "category": r["_id"]["category"], "count": r["count"]} for r in rows]
    except Exception:  # mongomock lacks $toLong: fall back to python bucketing over a capped projection
        out_map: dict = {}
        for d in c.store["security_events"].find(q, {"timestamp": 1, "prediction.category": 1}).limit(50000):
            b = int(d["timestamp"].timestamp() * 1000) // ms * ms
            k = (b, (d.get("prediction") or {}).get("category"))
            out_map[k] = out_map.get(k, 0) + 1
        out = [{"bucket_ms": b, "category": cat, "count": n} for (b, cat), n in sorted(out_map.items())]
    return {"bucket_minutes": bucket_minutes, "points": out}


@router.get("/events/{event_id}")
def get_event(event_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["security_events"].find_one({"_id": event_id})
    if not d:
        raise HTTPException(404, "event not found")
    return jsonable(strip_ground_truth(d))


@router.post("/events/batch")
def get_events_batch(body: dict, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    ids = list(body.get("ids", []))[:500]
    rows = c.repo.get_events_by_ids(ids)
    return jsonable({"items": rows, "requested": len(ids), "found": len(rows)})


# ------------------------------------------------------------------ alerts
@router.get("/alerts")
def list_alerts(page: int = 1, page_size: int = 50, severity: Optional[str] = None, category: Optional[str] = None, attack_type: Optional[str] = None,
                status: Optional[str] = None, source_ip: Optional[str] = None, q: Optional[str] = None, sort: str = "-created_at",
                c: Container = Depends(get_container), user: dict = Depends(current_user)):
    skip, limit = page_args(page, page_size)
    query: dict = {}
    for k, v in (("severity", severity), ("category", category), ("attack_type", attack_type), ("status", status), ("source_ip", source_ip)):
        if v:
            query[k] = v
    if q:
        query["$or"] = [{"source_ip": {"$regex": q}}, {"destination_ips": {"$regex": q}}, {"attack_type": {"$regex": q, "$options": "i"}}, {"_id": q}]
    direction = -1 if sort.startswith("-") else 1
    field = sort.lstrip("-") or "created_at"
    coll = c.store["alerts"]
    total = coll.count_documents(query)
    rows = list(coll.find(query).sort([(field, direction)]).skip(skip).limit(limit))
    return jsonable({"page": page, "page_size": limit, "total": total, "items": rows})


@router.get("/alerts/summary")
def alerts_summary(c: Container = Depends(get_container), user: dict = Depends(current_user)):
    coll = c.store["alerts"]
    by = lambda f: list(coll.aggregate([{"$group": {"_id": f"${f}", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}]))  # noqa: E731
    return jsonable({"total": coll.estimated_document_count(), "by_severity": by("severity"), "by_category": by("category"), "by_status": by("status"),
                     "by_attack_type": by("attack_type")[:25], "top_sources": by("source_ip")[:10]})


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["alerts"].find_one({"_id": alert_id})
    if not d:
        raise HTTPException(404, "alert not found")
    invs = list(c.store["investigations"].find({"alert_id": alert_id}, {"state": 0, "steps": 0}))
    profile = c.store["behavior_profiles"].find_one({"attack_type": d["attack_type"]}, {"profile_statement": 1, "top_features": 1, "dominant_protocols": 1, "attack_type": 1})
    return jsonable({**d, "investigations": invs, "profile": profile})


@router.get("/alerts/{alert_id}/events")
def alert_events(alert_id: str, limit: int = 100, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    d = c.store["alerts"].find_one({"_id": alert_id}, {"event_ids_sample": 1, "source_ip": 1, "first_seen": 1, "last_seen": 1, "attack_type": 1})
    if not d:
        raise HTTPException(404, "alert not found")
    rows = c.repo.get_events_by_ids(d.get("event_ids_sample", [])[:limit])
    return jsonable({"alert_id": alert_id, "items": rows, "note": "sample of the events that triggered the alert (event_ids_sample)"})


@router.post("/alerts/{alert_id}/status")
def set_alert_status(alert_id: str, body: dict, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    status = body.get("status")
    if status not in ("open", "investigating", "resolved", "false_positive", "closed"):
        raise HTTPException(400, "invalid status")
    r = c.store["alerts"].update_one({"_id": alert_id}, {"$set": {"status": status, "status_by": user.get("username")}})
    if not r.matched_count:
        raise HTTPException(404, "alert not found")
    return {"alert_id": alert_id, "status": status}


# ------------------------------------------------------------------ threat intelligence
@router.get("/threat-intel")
def ti_cache(limit: int = 200, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    rows = c.ti.list_cached(limit)
    return jsonable({"items": rows, "providers": {"virustotal": bool(c.settings.virustotal_api_key), "otx": bool(c.settings.otx_api_key)},
                     "note": "Cached provider responses. 'normalized' is the actual API result; 'ai_interpretation' (if present) is a separate Gemini reading and is never merged into evidence."})


@router.get("/threat-intel/lookup")
def ti_lookup(indicator: str = Query(..., min_length=1, max_length=253), provider: str = "all", c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Passive reputation lookup (cached). Private/documentation addresses are never sent to providers."""
    ind = indicator.strip()
    itype = indicator_type(ind)
    if itype == "unknown":
        raise HTTPException(400, "indicator must be an IPv4/IPv6 address, domain or file hash")
    out = {"indicator": ind, "type": itype}
    if provider in ("all", "virustotal"):
        out["virustotal"] = c.ti.check_virustotal(ind, itype)
    if provider in ("all", "otx"):
        out["otx"] = c.ti.check_otx(ind, itype)
    return jsonable(out)


@router.post("/threat-intel/interpret")
def ti_interpret(body: dict, c: Container = Depends(get_container), user: dict = Depends(current_user)):
    """Optional Gemini interpretation of an ACTUAL provider result; stored separately as `ai_interpretation`."""
    indicator, provider = body.get("indicator"), body.get("provider")
    doc = c.store["threat_intelligence"].find_one({"indicator": indicator, "provider": provider})
    if not doc:
        raise HTTPException(404, "no cached result for that indicator/provider — run a lookup first")
    if not c.llm.available:
        return {"indicator": indicator, "provider": provider, "ai_interpretation": None, "note": "Gemini not configured — interpretation unavailable; the API result above is unaffected."}
    import json as _json

    prompt = _json.dumps({"provider": provider, "indicator": indicator, "status": doc.get("status"), "normalized": doc.get("normalized"), "note": doc.get("note")}, default=str)
    resp = c.llm.generate_json(
        "You explain a threat-intelligence API result to a SOC analyst. Use ONLY the provided fields. If the status is not 'ok', say that no reputation data is available. JSON only.",
        prompt + '\nReturn {"interpretation": string (<=3 sentences), "caveats": [string]}', schema={"type": "object", "properties": {"interpretation": {"type": "string"}, "caveats": {"type": "array", "items": {"type": "string"}}}, "required": ["interpretation", "caveats"]},
        max_output_tokens=300)
    interp = {"text": resp.get("interpretation"), "caveats": resp.get("caveats", []), "model": c.settings.gemini_model} if resp else None
    c.store["threat_intelligence"].update_one({"_id": doc["_id"]}, {"$set": {"ai_interpretation": interp}})
    return jsonable({"indicator": indicator, "provider": provider, "api_result": {k: doc.get(k) for k in ("status", "normalized", "note", "fetched_at")}, "ai_interpretation": interp})


@router.get("/mitre/techniques")
def mitre_techniques(c: Container = Depends(get_container)):
    from backend.services.mitre import CURATED

    return jsonable({"bundle_loaded": c.mitre.bundle_loaded, "mappings": {k: c.mitre.map_attack_type(k) for k in sorted(CURATED)}})
