"""Phase 6 — SIEM alert generation from model predictions.

Malicious predictions are aggregated per (source_ip, predicted attack type) with a
sliding time gap; each cluster becomes an alert with:
* first/last seen, event count, distinct destinations/devices
* mean prediction confidence
* behavioural evidence: the alert's mean feature values vs the class profile vs benign (z-scores)
* severity from explicit, recorded rules (so the analyst can see *why*)
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional

import numpy as np

from backend.utils.ids import new_id
from backend.utils.timeutil import utcnow

log = logging.getLogger(__name__)

BASE_SEVERITY = {
    "DDoS": 3, "DoS": 2, "Web-Based": 3, "Brute Force": 2, "Spoofing": 2, "Reconnaissance": 1, "Benign": 0,
}
SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
GAP_SECONDS = 600
MAX_SAMPLE_IDS = 200


def _severity(category: str, event_count: int, n_targets: int, confidence: float) -> tuple[str, List[str]]:
    score = BASE_SEVERITY.get(category, 1)
    rationale = [f"base severity for category {category} = {SEVERITY_NAMES[score]}"]
    if n_targets >= 3:
        score += 1
        rationale.append(f"{n_targets} distinct targets → +1")
    if event_count >= 200 and category in ("DDoS", "DoS"):
        score += 1
        rationale.append(f"{event_count} flood events → +1")
    if confidence < 0.6:
        score -= 1
        rationale.append(f"mean model confidence {confidence:.2f} < 0.60 → −1")
    score = max(0, min(4, score))
    return SEVERITY_NAMES[score], rationale


def _behavioral_evidence(events: List[dict], profile: Optional[dict]) -> dict:
    if not profile:
        return {"top_features": [], "profile_version": None, "note": "no behaviour profile available"}
    top = profile.get("top_features", [])[:6]
    stats = profile.get("feature_stats", {})
    rows = []
    for f in top:
        vals = [e["features"].get(f) for e in events if e.get("features") and e["features"].get(f) is not None]
        if not vals:
            continue
        v = float(np.mean(vals))
        st = stats.get(f, {})
        b_std = st.get("benign_std") or 0.0
        z = (v - st.get("benign_mean", 0.0)) / b_std if b_std else 0.0
        rows.append({
            "feature": f, "alert_mean": v, "profile_mean": st.get("class_mean"), "benign_mean": st.get("benign_mean"),
            "z_vs_benign": float(np.clip(z, -50, 50)),
            "shap_mean_abs": profile.get("importance", {}).get("shap_mean_abs", {}).get(f),
        })
    return {"top_features": rows, "profile_version": profile.get("model_version"),
            "profile_statement": profile.get("profile_statement"),
            "dominant_protocols": profile.get("dominant_protocols", [])}


def generate_alerts(events: List[dict], profiles_by_label: Dict[str, dict], model_version: str,
                    gap_seconds: int = GAP_SECONDS) -> List[dict]:
    """events must carry prediction.{label, attack_type, category, confidence}. Returns alert docs."""
    buckets: Dict[tuple, List[dict]] = defaultdict(list)
    for e in events:
        p = e.get("prediction") or {}
        if not p or p.get("category") in (None, "Benign"):
            continue
        buckets[(e["source_ip"], p["attack_type"])].append(e)

    alerts: List[dict] = []
    for (src, atype), evs in buckets.items():
        evs.sort(key=lambda e: e["timestamp"])
        cluster: List[dict] = []
        clusters: List[List[dict]] = []
        for e in evs:
            if cluster and (e["timestamp"] - cluster[-1]["timestamp"]) > timedelta(seconds=gap_seconds):
                clusters.append(cluster)
                cluster = []
            cluster.append(e)
        if cluster:
            clusters.append(cluster)
        for cl in clusters:
            p0 = cl[0]["prediction"]
            dsts = sorted({e["destination_ip"] for e in cl})
            devs = sorted({e.get("device_id") for e in cl if e.get("device_id")})
            conf = float(np.mean([e["prediction"].get("confidence", 0.0) for e in cl]))
            sev, rationale = _severity(p0["category"], len(cl), len(dsts), conf)
            protocols = sorted({e.get("protocol") for e in cl if e.get("protocol")})
            profile = profiles_by_label.get(p0["label"])
            alerts.append({
                "_id": new_id("alr"),
                "created_at": utcnow(),
                "first_seen": cl[0]["timestamp"],
                "last_seen": cl[-1]["timestamp"],
                "attack_type": atype,
                "category": p0["category"],
                "predicted_label": p0["label"],
                "severity": sev,
                "severity_rationale": rationale,
                "source_ip": src,
                "destination_ips": dsts,
                "device_ids": devs,
                "protocol": protocols[0] if protocols else None,
                "protocols": protocols,
                "event_count": len(cl),
                "event_ids_sample": [e["_id"] for e in cl[:MAX_SAMPLE_IDS]],
                "confidence_mean": conf,
                "model_version": model_version,
                "behavioral_evidence": _behavioral_evidence(cl, profile),
                "profile": {"profile_statement": (profile or {}).get("profile_statement"),
                            "dominant_protocols": (profile or {}).get("dominant_protocols", []),
                            "model_version": (profile or {}).get("model_version")},
                "status": "new",
                "investigation_ids": [],
                "provenance": cl[0].get("context", {}).get("provenance", "unknown"),
                "data_source": cl[0].get("log_source"),
            })
    alerts.sort(key=lambda a: a["first_seen"])
    log.info("generated %d alerts from %d malicious buckets", len(alerts), len(buckets))
    return alerts
