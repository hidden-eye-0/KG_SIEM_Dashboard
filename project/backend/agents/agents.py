"""The eight logical agents (architecture review §3).

Agents 1 (Data Ingestion) and 2 (Preprocessing & Behavioral Analysis) run offline in
``ml/pipeline.py``.  Agents 3–8 below are the online investigation agents implemented
as LangGraph node functions that read/write the shared ``InvestigationState``.

LLM usage: Agent 3 (hypothesis), Agent 6 (action selection / reassessment) and Agent 8
(narrative) use Gemini when available; Agents 4, 5 and 7 are deterministic.  Every
agent works without the LLM (heuristic / template fallbacks) so the investigation loop
never depends on an external service.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from backend.agents.policy import Policy
from backend.agents.requirements import PRIORITY_WEIGHT, Requirement, build_requirements, fixed_baseline_plan
from backend.agents.state import (
    ActionRecord, AgentAction, CandidateAction, EvidenceGap, EvidenceItem, Hypothesis, InvestigationState, ToolCall,
)
from backend.config import Settings
from backend.services.gemini import GeminiClient
from backend.services.graph_store import GraphStore
from backend.services.mitre import MitreService
from backend.tools.registry import EVIDENCE_TOOLS, GRAPH_TOOLS, TI_TOOLS, ToolRegistry
from backend.utils.ids import digest, new_id
from backend.utils.ipaddr import classify_ip
from backend.utils.timeutil import parse_dt, to_iso, utcnow

log = logging.getLogger(__name__)

HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "statement": {"type": "string"},
        "confidence": {"type": "number"},
        "alternatives": {"type": "array", "items": {"type": "string"}},
        "key_questions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["statement", "confidence"],
}

REASSESS_SCHEMA = {
    "type": "object",
    "properties": {
        "statement": {"type": "string"},
        "confidence": {"type": "number"},
        "stages": {"type": "array", "items": {"type": "string"}},
        "contradictions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["statement", "confidence"],
}

CATEGORY_ORDER = {"Reconnaissance": 0, "Brute Force": 1, "Spoofing": 1, "Web-Based": 2, "DoS": 3, "DDoS": 3}


def _log(state: InvestigationState, agent: str, node: str, title: str, detail: str = "", tool: Optional[str] = None,
         args: Optional[dict] = None, evidence_ids: Optional[List[str]] = None, llm_used: bool = False,
         latency_ms: float = 0.0, status: str = "ok") -> AgentAction:
    return AgentAction(step=state.get("investigation_step", 0), agent=agent, node=node, title=title, detail=detail,
                       tool=tool, args=args or {}, evidence_ids=evidence_ids or [], llm_used=llm_used,
                       latency_ms=round(latency_ms, 1), timestamp=to_iso(utcnow()), status=status)


class AgentContext:
    """Shared services handed to every node."""

    def __init__(self, tools: ToolRegistry, graph: GraphStore, mitre: MitreService, llm: Optional[GeminiClient],
                 settings: Settings, policy_mode: str, mode: str, profiles_by_type: Dict[str, dict],
                 emit=None):
        self.tools, self.graph, self.mitre, self.llm, self.settings = tools, graph, mitre, llm, settings
        self.policy = Policy(policy_mode, llm)
        self.policy_mode = policy_mode
        self.mode = mode
        self.profiles_by_type = profiles_by_type
        self.requirements: List[Requirement] = build_requirements(settings.max_time_window_seconds)
        self.emit = emit or (lambda action: None)


# =============================================================================
# Agent 3 — Alert Investigation Agent
# =============================================================================
def interpret_alert(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    alert = state["alert"]
    src = alert["source_ip"]
    entities: Dict[str, Any] = {}
    ipinfo = classify_ip(src)
    entities[f"IP:{src}"] = {"key": f"IP:{src}", "type": "IP", "value": src, "role": "source",
                             "first_seen": to_iso(parse_dt(alert["first_seen"])), "last_seen": to_iso(parse_dt(alert["last_seen"])),
                             "evidence_ids": [], "properties": {"is_private": ipinfo["is_private"], "is_documentation_range": ipinfo["is_reserved_documentation"]}}
    for ip in alert.get("destination_ips", []):
        entities[f"IP:{ip}"] = {"key": f"IP:{ip}", "type": "IP", "value": ip, "role": "target", "first_seen": to_iso(parse_dt(alert["first_seen"])),
                                "last_seen": to_iso(parse_dt(alert["last_seen"])), "evidence_ids": [], "properties": {"is_private": classify_ip(ip)["is_private"]}}
    for d in alert.get("device_ids", []):
        entities[f"Device:{d}"] = {"key": f"Device:{d}", "type": "Device", "value": d, "role": "target", "first_seen": None, "last_seen": None,
                                   "evidence_ids": [], "properties": {}}

    profile = ctx.profiles_by_type.get(alert["attack_type"], {})
    be = alert.get("behavioral_evidence", {}) or {}
    top_feats = [f"{r['feature']} (z={r['z_vs_benign']:+.1f})" for r in be.get("top_features", [])[:4]]
    base_statement = (
        f"{alert['attack_type']} ({alert['category']}) activity from {src} against "
        f"{len(alert.get('destination_ips', []))} destination(s) between {alert['first_seen']} and {alert['last_seen']}; "
        f"{alert['event_count']} flows predicted as {alert['predicted_label']} with mean confidence {alert['confidence_mean']:.2f}. "
        + (f"Behavioral indicators: {', '.join(top_feats)}. " if top_feats else "")
        + "The flow-level evidence supports the labelled class; the underlying actions are not directly observable from flow features."
    )
    hyp = Hypothesis(id=new_id("hyp"), statement=base_statement, attack_type=alert["attack_type"], category=alert["category"],
                     confidence=min(0.9, float(alert.get("confidence_mean", 0.5)) * 0.8), stages=[alert["attack_type"]],
                     supporting_evidence_ids=[], contradicting_evidence_ids=[], alternatives=[], updated_at_step=0)
    llm_used = False
    if ctx.policy_mode == "llm" and ctx.llm and ctx.llm.available and state["budget"]["llm_calls_used"] < state["budget"]["max_llm_calls"]:
        prompt = json.dumps({
            "alert": {k: alert.get(k) for k in ("attack_type", "category", "severity", "severity_rationale", "source_ip", "destination_ips", "device_ids", "protocols", "event_count", "confidence_mean", "first_seen", "last_seen")},
            "behavioral_evidence": be,
            "behavior_profile_statement": profile.get("profile_statement"),
            "instruction": "Write a one-paragraph investigation hypothesis grounded ONLY in these facts, give a confidence in [0,1], list up to 3 alternative explanations and up to 4 key questions the investigation must answer. Use cautious wording: flow features are behavioral evidence of the labelled class, not proof of specific actions.",
        }, default=str)
        resp = ctx.llm.generate_json("You are the Alert Investigation Agent of a SOC. Respond with JSON only.", prompt, schema=HYPOTHESIS_SCHEMA, max_output_tokens=700)
        state["budget"]["llm_calls_used"] += 1
        if resp and resp.get("statement"):
            hyp["statement"] = str(resp["statement"])[:1200]
            hyp["confidence"] = float(min(max(resp.get("confidence", hyp["confidence"]), 0.05), 0.95))
            hyp["alternatives"] = [str(a)[:200] for a in resp.get("alternatives", [])][:3]
            hyp["key_questions"] = [str(q)[:200] for q in resp.get("key_questions", [])][:4]
            llm_used = True

    action = _log(state, "AlertInvestigationAgent", "interpret_alert", "Alert received and interpreted",
                  f"{len(entities)} entities identified; initial hypothesis: {hyp['statement'][:180]}…", llm_used=llm_used,
                  latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"entities": entities, "current_hypothesis": hyp, "confidence": hyp["confidence"], "agent_log": [action],
            "status": "running"}


# =============================================================================
# Agent 5 — Knowledge Graph Agent (deterministic derivation rules R1–R8)
# =============================================================================
def _attack_key(inv: str, source_ip: str, attack_type: str) -> str:
    """Attack node = activity of one attack type by one source within this investigation."""
    return f"Attack:{inv}:{source_ip}:{attack_type.replace(' ', '_')}"


def _alert_attack_key(state: InvestigationState, attack_type: str) -> str:
    return _attack_key(state["investigation_id"], state["alert"]["source_ip"], attack_type)


def _graph_node_budget_ok(state: InvestigationState, ctx: AgentContext) -> bool:
    return ctx.graph.count_nodes(state["investigation_id"]) < state["budget"]["max_graph_nodes"]


def build_initial_graph(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    inv, alert = state["investigation_id"], state["alert"]
    g = ctx.graph
    ev_ids = alert.get("event_ids_sample", [])[:50]
    g.merge_node("Investigation", f"Investigation:{inv}", {"mode": state["mode"], "started_at": to_iso(utcnow())}, inv)
    g.merge_node("Alert", f"Alert:{alert['_id']}", {"severity": alert["severity"], "category": alert["category"], "attack_type": alert["attack_type"],
                                                      "created_at": to_iso(parse_dt(alert["created_at"])), "event_count": alert["event_count"]}, inv, ev_ids)
    g.merge_relationship(f"Alert:{alert['_id']}", "PART_OF", f"Investigation:{inv}", inv, {"derived_by": "R2", "confidence": 1.0})
    src = alert["source_ip"]
    g.merge_node("IP", f"IP:{src}", {"address": src, **classify_ip(src)}, inv, ev_ids)
    akey = _alert_attack_key(state, alert["attack_type"])
    g.merge_node("Attack", akey, {"attack_type": alert["attack_type"], "category": alert["category"], "predicted_label": alert["predicted_label"], "source_ip": src,
                                  "first_seen": to_iso(parse_dt(alert["first_seen"])), "last_seen": to_iso(parse_dt(alert["last_seen"])),
                                  "event_count": alert["event_count"], "confidence": alert["confidence_mean"], "alert_id": alert["_id"], "severity": alert["severity"]}, inv, ev_ids)
    g.merge_relationship(f"IP:{src}", "PERFORMS", akey, inv, {"derived_by": "R2", "confidence": alert["confidence_mean"], "first_seen": to_iso(parse_dt(alert["first_seen"])),
                                                              "last_seen": to_iso(parse_dt(alert["last_seen"])), "evidence_count": alert["event_count"]}, ev_ids)
    g.merge_relationship(akey, "GENERATES", f"Alert:{alert['_id']}", inv, {"derived_by": "R2", "confidence": 1.0}, ev_ids)
    g.merge_relationship(akey, "PART_OF", f"Investigation:{inv}", inv, {"derived_by": "R2", "confidence": 1.0})
    devices = {d: None for d in alert.get("device_ids", [])}
    for ip in alert.get("destination_ips", []):
        g.merge_node("IP", f"IP:{ip}", {"address": ip, **classify_ip(ip)}, inv, ev_ids)
        g.merge_relationship(f"IP:{src}", "COMMUNICATES_WITH", f"IP:{ip}", inv, {"derived_by": "R1", "first_seen": to_iso(parse_dt(alert["first_seen"])),
                                                                                  "last_seen": to_iso(parse_dt(alert["last_seen"])), "evidence_count": alert["event_count"], "confidence": 1.0}, ev_ids)
        g.merge_relationship(akey, "TARGETS", f"IP:{ip}", inv, {"derived_by": "R2", "confidence": alert["confidence_mean"], "evidence_count": alert["event_count"]}, ev_ids)
    for d in devices:
        g.merge_node("Device", f"Device:{d}", {"device_id": d}, inv, ev_ids)
        g.merge_relationship(akey, "TARGETS", f"Device:{d}", inv, {"derived_by": "R2", "confidence": alert["confidence_mean"], "evidence_count": alert["event_count"]}, ev_ids)
    # R4 behaviour node
    be = alert.get("behavioral_evidence") or {}
    if be.get("top_features"):
        bkey = f"Behavior:{inv}:{alert['attack_type'].replace(' ', '_')}"
        g.merge_node("Behavior", bkey, {"top_features": json.dumps([r["feature"] for r in be["top_features"]]),
                                        "z_scores": json.dumps({r["feature"]: round(r["z_vs_benign"], 2) for r in be["top_features"]}),
                                        "profile_version": be.get("profile_version")}, inv, ev_ids)
        g.merge_relationship(bkey, "INDICATES", akey, inv, {"derived_by": "R4", "confidence": alert["confidence_mean"], "evidence_count": alert["event_count"]}, ev_ids)
    summary = g.summary(inv)
    summary["last_updated_step"] = state.get("investigation_step", 0)
    summary["truncated"] = False
    action = _log(state, "KnowledgeGraphAgent", "build_initial_graph", "Initial knowledge graph built",
                  f"{summary['node_count']} nodes / {summary['edge_count']} edges derived from the alert (rules R1, R2, R4)", latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"graph_state": summary, "agent_log": [action]}


def _graph_from_alerts(state: InvestigationState, ctx: AgentContext, res: dict, ev_id: Optional[str], ev_ids: List[str],
                       entities: Dict[str, Any], can_add) -> None:
    """R2 for related alerts: each alert becomes an Attack node performed by its source."""
    inv, g = state["investigation_id"], ctx.graph
    for a in res["records"]:
        if not can_add():
            break
        key = f"Alert:{a['_id']}"
        sample = a.get("event_ids_sample", [])[:20]
        g.merge_node("Alert", key, {"severity": a["severity"], "category": a["category"], "attack_type": a["attack_type"],
                                    "created_at": to_iso(parse_dt(a["created_at"])), "event_count": a["event_count"]}, inv, sample)
        akey = _attack_key(inv, a["source_ip"], a["attack_type"])
        g.merge_node("Attack", akey, {"attack_type": a["attack_type"], "category": a["category"], "predicted_label": a["predicted_label"], "source_ip": a["source_ip"],
                                      "first_seen": to_iso(parse_dt(a["first_seen"])), "last_seen": to_iso(parse_dt(a["last_seen"])),
                                      "event_count": a["event_count"], "confidence": a["confidence_mean"], "alert_id": a["_id"]}, inv, sample)
        g.merge_node("IP", f"IP:{a['source_ip']}", {"address": a["source_ip"], **classify_ip(a["source_ip"])}, inv, sample)
        g.merge_relationship(f"IP:{a['source_ip']}", "PERFORMS", akey, inv, {"derived_by": "R2", "first_seen": to_iso(parse_dt(a["first_seen"])),
                                                                            "last_seen": to_iso(parse_dt(a["last_seen"])), "evidence_count": a["event_count"],
                                                                            "confidence": a["confidence_mean"], "evidence_id": ev_id}, sample)
        g.merge_relationship(akey, "GENERATES", key, inv, {"derived_by": "R2", "confidence": 1.0}, sample)
        g.merge_relationship(akey, "PART_OF", f"Investigation:{inv}", inv, {"derived_by": "R2", "confidence": 1.0})
        for d_ip in a.get("destination_ips", [])[:10]:
            g.merge_node("IP", f"IP:{d_ip}", {"address": d_ip, **classify_ip(d_ip)}, inv)
            g.merge_relationship(akey, "TARGETS", f"IP:{d_ip}", inv, {"derived_by": "R2", "evidence_count": a["event_count"], "confidence": 1.0}, sample)
        for d in a.get("device_ids", [])[:10]:
            g.merge_node("Device", f"Device:{d}", {"device_id": d}, inv)
            g.merge_relationship(akey, "TARGETS", f"Device:{d}", inv, {"derived_by": "R2", "evidence_count": a["event_count"], "confidence": 1.0}, sample)
        if akey not in entities:
            entities[akey] = {"key": akey, "type": "Attack", "value": a["attack_type"], "role": "related", "first_seen": to_iso(parse_dt(a["first_seen"])),
                              "last_seen": to_iso(parse_dt(a["last_seen"])), "evidence_ids": ev_ids, "properties": {"category": a["category"], "alert_id": a["_id"]}}
        if f"Alert:{a['_id']}" not in entities:
            entities[key] = {"key": key, "type": "Alert", "value": a["_id"], "role": "related", "first_seen": to_iso(parse_dt(a["first_seen"])),
                             "last_seen": to_iso(parse_dt(a["last_seen"])), "evidence_ids": ev_ids, "properties": {"attack_type": a["attack_type"], "severity": a["severity"]}}


def update_graph(state: InvestigationState, ctx: AgentContext) -> dict:
    """Apply derivation rules to the most recent tool result."""
    t0 = time.perf_counter()
    res = state.get("last_tool_result")
    if not res:
        return {}
    inv, alert = state["investigation_id"], state["alert"]
    g = ctx.graph
    ev_id = res.get("evidence_id")
    ev_ids = [ev_id] if ev_id else []
    added_nodes = 0
    truncated = False
    entities = dict(state.get("entities", {}))
    new_edges: List[str] = []

    def can_add() -> bool:
        nonlocal truncated
        ok = _graph_node_budget_ok(state, ctx)
        if not ok:
            truncated = True
        return ok

    tool = res["tool"]
    if tool == "search_alerts" and res.get("records"):
        _graph_from_alerts(state, ctx, res, ev_id, ev_ids, entities, can_add)
        added_nodes += 1
    elif tool in EVIDENCE_TOOLS and res.get("records"):
        # R3 evidence set node
        if ev_id and can_add():
            g.merge_node("EvidenceSet", f"EvidenceSet:{ev_id}", {"tool": tool, "count": res["count"], "total_matched": res["total_matched"],
                                                                  "query_digest": res.get("query_digest"), "first_seen": res["summary"].get("first_seen"),
                                                                  "last_seen": res["summary"].get("last_seen")}, inv, res.get("record_ids", [])[:50])
            added_nodes += 1
        # R1/R2 per (src, dst, attack_type) clusters
        clusters: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for r in res["records"]:
            p = r.get("prediction") or {}
            key = (r["source_ip"], r["destination_ip"], p.get("attack_type") or "unknown")
            c = clusters.setdefault(key, {"count": 0, "first": r["timestamp"], "last": r["timestamp"], "ids": [], "category": p.get("category"),
                                          "label": p.get("label"), "conf": [], "device": r.get("device_id")})
            c["count"] += 1
            c["first"] = min(c["first"], r["timestamp"])
            c["last"] = max(c["last"], r["timestamp"])
            if len(c["ids"]) < 50:
                c["ids"].append(r["_id"])
            c["conf"].append(p.get("confidence", 0.0))
        for (s_ip, d_ip, atype), c in clusters.items():
            for ip in (s_ip, d_ip):
                if f"IP:{ip}" not in entities:
                    if not can_add():
                        break
                    added_nodes += 1
                    entities[f"IP:{ip}"] = {"key": f"IP:{ip}", "type": "IP", "value": ip, "role": "related", "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]),
                                            "evidence_ids": ev_ids, "properties": classify_ip(ip)}
                g.merge_node("IP", f"IP:{ip}", {"address": ip, **classify_ip(ip)}, inv, c["ids"])
            g.merge_relationship(f"IP:{s_ip}", "COMMUNICATES_WITH", f"IP:{d_ip}", inv, {"derived_by": "R1", "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]),
                                                                                     "evidence_count": c["count"], "confidence": 1.0, "evidence_id": ev_id}, c["ids"])
            new_edges.append(f"{s_ip}→{d_ip}")
            if c["device"]:
                dkey = f"Device:{c['device']}"
                if dkey not in entities and can_add():
                    entities[dkey] = {"key": dkey, "type": "Device", "value": c["device"], "role": "related", "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]), "evidence_ids": ev_ids, "properties": {}}
                    added_nodes += 1
                g.merge_node("Device", dkey, {"device_id": c["device"], "ip": d_ip}, inv, c["ids"])
            if c["category"] and c["category"] != "Benign":
                akey = _attack_key(inv, s_ip, atype)
                if akey not in entities:
                    if not can_add():
                        continue
                    added_nodes += 1
                    entities[akey] = {"key": akey, "type": "Attack", "value": atype, "role": "related", "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]), "evidence_ids": ev_ids,
                                      "properties": {"category": c["category"]}}
                g.merge_node("Attack", akey, {"attack_type": atype, "category": c["category"], "predicted_label": c["label"], "source_ip": s_ip, "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]),
                                              "event_count": c["count"], "confidence": sum(c["conf"]) / max(len(c["conf"]), 1)}, inv, c["ids"])
                g.merge_relationship(f"IP:{s_ip}", "PERFORMS", akey, inv, {"derived_by": "R2", "first_seen": to_iso(c["first"]), "last_seen": to_iso(c["last"]), "evidence_count": c["count"],
                                                                         "confidence": sum(c["conf"]) / max(len(c["conf"]), 1), "evidence_id": ev_id}, c["ids"])
                g.merge_relationship(akey, "TARGETS", f"IP:{d_ip}", inv, {"derived_by": "R2", "evidence_count": c["count"], "confidence": 1.0, "evidence_id": ev_id}, c["ids"])
                if c["device"]:
                    g.merge_relationship(akey, "TARGETS", f"Device:{c['device']}", inv, {"derived_by": "R2", "evidence_count": c["count"], "confidence": 1.0, "evidence_id": ev_id}, c["ids"])
                g.merge_relationship(akey, "PART_OF", f"Investigation:{inv}", inv, {"derived_by": "R2", "confidence": 1.0})
                if ev_id:
                    g.merge_relationship(akey, "SUPPORTED_BY", f"EvidenceSet:{ev_id}", inv, {"derived_by": "R3", "evidence_count": c["count"], "confidence": 1.0}, c["ids"])
    elif tool in TI_TOOLS and res.get("ti"):
        # R5 IOC node (only when the provider actually returned data)
        ti = res["ti"]
        ind = ti["indicator"]
        if ti["status"] in ("ok", "not_found") and can_add():
            ikey = f"IOC:{ti['provider']}:{ind}"
            norm = ti.get("normalized") or {}
            g.merge_node("IOC", ikey, {"provider": ti["provider"], "status": ti["status"], "indicator": ind, "verdict": norm.get("verdict"),
                                       "malicious_votes": norm.get("malicious_votes"), "pulse_count": norm.get("pulse_count"), "fetched_at": to_iso(ti.get("fetched_at"))}, inv)
            g.merge_relationship(f"IP:{ind}" if ti["type"] == "ip" else f"Domain:{ind}", "ASSOCIATED_WITH", ikey, inv, {"derived_by": "R5", "provider": ti["provider"], "confidence": 1.0})
            entities[ikey] = {"key": ikey, "type": "IOC", "value": ind, "role": "indicator", "first_seen": None, "last_seen": None, "evidence_ids": [], "properties": {"provider": ti["provider"], "status": ti["status"]}}
            added_nodes += 1
            if norm.get("verdict") in ("malicious", "reported_in_pulses"):
                akey = _alert_attack_key(state, alert["attack_type"])
                g.merge_relationship(ikey, "INDICATES", akey, inv, {"derived_by": "R5", "confidence": 0.6})
    elif tool == "map_attack_to_mitre" and res.get("mappings"):
        sg = g.get_subgraph(inv, limit=2000)
        attack_keys_by_type: Dict[str, List[str]] = {}
        for n in sg["nodes"]:
            if n["label"] == "Attack" and n["properties"].get("attack_type"):
                attack_keys_by_type.setdefault(n["properties"]["attack_type"], []).append(n["key"])
        for m in res["mappings"]:
            targets_keys = attack_keys_by_type.get(m["attack_type"]) or [_alert_attack_key(state, m["attack_type"])]
            tkey = f"MITRE:{m['technique_id']}"
            if can_add():
                g.merge_node("MITRETechnique", tkey, {"technique_id": m["technique_id"], "name": m["name"], "tactic": m["tactic"], "url": m["url"],
                                                      "verified": m["verified_against_bundle"]}, inv)
                for akey in targets_keys:
                    g.merge_node("Attack", akey, {"attack_type": m["attack_type"]}, inv)
                    g.merge_relationship(akey, "MAPS_TO", tkey, inv, {"derived_by": "R6", "confidence": {"high": 0.9, "medium": 0.6, "low": 0.35}[m["confidence"]],
                                                                      "rationale": m["rationale"], "mapping_confidence": m["confidence"]})
                added_nodes += 1

    # R7 temporal ordering between Attack nodes of the same source
    _apply_occurs_before(state, ctx)

    summary = g.summary(inv)
    summary["last_updated_step"] = state.get("investigation_step", 0)
    summary["truncated"] = truncated or bool(state.get("graph_state", {}).get("truncated"))
    action = _log(state, "KnowledgeGraphAgent", "update_graph", "Knowledge graph updated",
                  f"{summary['node_count']} nodes / {summary['edge_count']} edges after applying evidence {ev_id or ''}" + (" (node budget reached)" if truncated else ""),
                  evidence_ids=ev_ids, latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"graph_state": summary, "entities": entities, "agent_log": [action]}


def _apply_occurs_before(state: InvestigationState, ctx: AgentContext) -> None:
    inv = state["investigation_id"]
    sg = ctx.graph.get_subgraph(inv, limit=2000)
    attacks = [n for n in sg["nodes"] if n["label"] == "Attack" and n["properties"].get("first_seen")]
    perf = {}
    for e in sg["edges"]:
        if e["type"] == "PERFORMS":
            perf.setdefault(e["target"], set()).add(e["source"])
    attacks.sort(key=lambda n: n["properties"]["first_seen"])
    for i, a in enumerate(attacks):
        for b in attacks[i + 1:]:
            if perf.get(a["key"], set()) & perf.get(b["key"], set()) and a["properties"].get("last_seen", "") <= b["properties"]["first_seen"]:
                gap = (parse_dt(b["properties"]["first_seen"]) - parse_dt(a["properties"]["last_seen"])).total_seconds()
                ctx.graph.merge_relationship(a["key"], "OCCURS_BEFORE", b["key"], inv, {"derived_by": "R7", "gap_seconds": gap, "confidence": 1.0})


# =============================================================================
# Agent 6 — Adaptive Evidence Collection Agent (assess_gaps / decide_action / reassess)
# =============================================================================
def assess_gaps(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    step = state.get("investigation_step", 0)
    existing = {g["requirement_id"]: g for g in state.get("missing_evidence", [])}
    gaps: List[EvidenceGap] = []
    candidates: List[CandidateAction] = []
    executed = {c["query_digest"] for c in state.get("tool_history", [])}
    unresolvable = {g["requirement_id"] for g in existing.values() if g["status"] == "unresolvable"}

    if state["mode"] == "baseline":
        done = {c["args"].get("_action_id") for c in state.get("tool_history", [])} | {a["action_id"] for a in (state.get("last_action") and [state["last_action"]] or [])}
        plan = [c for c in fixed_baseline_plan(state) if c["action_id"] not in {h.get("action_id") for h in state.get("executed_action_ids", [])}]
        return {"missing_evidence": [], "candidate_actions": plan, "agent_log": []}

    for req in ctx.requirements:
        if not req.applies(state):
            continue
        sat = req.satisfied(state)
        prev = existing.get(req.id)
        if sat:
            if prev and prev["status"] == "open":
                gaps.append({**prev, "status": "resolved", "resolved_by": prev.get("resolved_by") or f"step {step}"})
            elif prev:
                gaps.append(prev)
            continue
        status = "unresolvable" if req.id in unresolvable else "open"
        gaps.append(EvidenceGap(gap_id=prev["gap_id"] if prev else new_id("gap"), requirement_id=req.id, description=req.description,
                                priority=req.priority, status=status, resolved_by=None, opened_at_step=prev["opened_at_step"] if prev else step))
        if status == "open":
            for c in req.candidates(state):
                d = digest({"tool": c["tool"], "args": {k: v for k, v in c["args"].items() if k != "alert"} | ({"alert_id": state["alert_id"]} if "alert" in c["args"] else {})})
                if d in executed:
                    continue  # never repeat an identical query
                c["expected_gain"] = round(c["expected_gain"] * PRIORITY_WEIGHT[req.priority] / 2.0, 3)
                c["utility"] = round(c["expected_gain"] / max(c["cost"], 0.1), 3)
                candidates.append(c)
    # a requirement whose candidates were all executed but is still unsatisfied is unresolvable
    open_ids = {g["requirement_id"] for g in gaps if g["status"] == "open"}
    cand_ids = {cid for c in candidates for cid in c["closes_gap_ids"]}
    for g in gaps:
        if g["status"] == "open" and g["requirement_id"] not in cand_ids and g["requirement_id"] in open_ids:
            g["status"] = "unresolvable"
            g["resolved_by"] = "all candidate queries executed without satisfying the requirement"
    candidates.sort(key=lambda c: (-c["utility"], c["action_id"]))
    n_open = sum(1 for g in gaps if g["status"] == "open")
    action = _log(state, "AdaptiveEvidenceAgent", "assess_gaps", "Evidence gaps assessed",
                  f"{n_open} open gap(s), {len(candidates)} candidate action(s): " + ", ".join(f"{c['tool']}[{c['utility']}]" for c in candidates[:4]),
                  latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"missing_evidence": gaps, "candidate_actions": candidates, "agent_log": [action]}


def _sufficiency(state: InvestigationState, gaps: List[EvidenceGap]) -> dict:
    applicable = [g for g in gaps]
    weights = sum(PRIORITY_WEIGHT[g["priority"]] for g in applicable) or 1.0
    resolved = sum(PRIORITY_WEIGHT[g["priority"]] for g in applicable if g["status"] in ("resolved", "unresolvable"))
    coverage = resolved / weights
    open_critical = sum(1 for g in applicable if g["status"] == "open" and g["priority"] == "critical")
    open_high = sum(1 for g in applicable if g["status"] == "open" and g["priority"] == "high")
    hyp_conf = float((state.get("current_hypothesis") or {}).get("confidence", 0.5))
    gs = state.get("graph_state") or {}
    attacks = gs.get("by_type", {}).get("Attack", 0)
    conn = min(1.0, (gs.get("edge_count", 0) / max(gs.get("node_count", 1), 1)) / 2.0)
    novelty = [e.get("novelty", 0) for e in state.get("evidence", [])[-3:]]
    score = 0.6 * coverage + 0.25 * hyp_conf + 0.15 * conn
    return {"score": round(score, 3), "coverage": round(coverage, 3), "hypothesis_confidence": round(hyp_conf, 3), "chain_connectivity": round(conn, 3),
            "open_critical": open_critical, "open_high": open_high, "novelty_last_k": novelty, "attack_nodes": attacks,
            "reason": f"coverage {coverage:.2f} (weighted gaps resolved), hypothesis confidence {hyp_conf:.2f}, graph connectivity {conn:.2f}"}


def decide_action(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    budget = state["budget"]
    step = state.get("investigation_step", 0)
    gaps = state.get("missing_evidence", [])
    cands = list(state.get("candidate_actions", []))
    suff = _sufficiency(state, gaps)
    elapsed = (utcnow() - parse_dt(budget["started_at"])).total_seconds()

    def stop(reason: str, detail: str):
        action = _log(state, "AdaptiveEvidenceAgent", "decide_action", f"Stop: {reason}", detail, latency_ms=(time.perf_counter() - t0) * 1000)
        ctx.emit(action)
        return {"last_action": None, "termination_reason": reason, "sufficiency": suff, "agent_log": [action]}

    if budget["steps_used"] >= budget["max_steps"]:
        return stop("max_steps", f"MAX_INVESTIGATION_STEPS={budget['max_steps']} reached")
    if elapsed > budget["timeout_seconds"]:
        return stop("timeout", f"INVESTIGATION_TIMEOUT_SECONDS={budget['timeout_seconds']} exceeded")
    if not cands:
        return stop("no_candidates", "no relevant additional evidence can be requested for the current hypothesis" if state["mode"] != "baseline" else "fixed baseline plan complete")
    if state["mode"] != "baseline":
        if suff["score"] >= ctx.settings.sufficiency_threshold and suff["open_critical"] == 0:
            return stop("sufficient", f"sufficiency {suff['score']:.2f} ≥ {ctx.settings.sufficiency_threshold} with no open critical gaps")
        nov = suff["novelty_last_k"]
        if len(nov) >= 3 and all(n == 0 for n in nov) and suff["open_critical"] == 0 and suff["open_high"] == 0:
            return stop("diminishing_returns", "last 3 retrievals produced no new records or entities and no critical/high gap remains")
    # TI budget
    if budget["ti_lookups_used"] >= budget["max_ti_lookups"]:
        cands = [c for c in cands if c["tool"] not in TI_TOOLS]
        if not cands:
            return stop("budget", "threat-intelligence lookup budget exhausted and no other candidates")

    if state["mode"] == "baseline":
        choice, meta = cands[0], {"chosen_by": "fixed", "reasoning": "fixed baseline plan", "alternatives_considered": 0}
    else:
        choice, meta = ctx.policy.choose(state, cands)
        if choice is None and meta.get("stop"):
            if suff["open_critical"] == 0:
                return stop("sufficient", f"policy chose STOP: {meta.get('reasoning', '')[:200]}")
            choice, meta2 = Policy._heuristic(cands)
            meta = {**meta2, "reasoning": "LLM proposed STOP but critical gaps remain; heuristic override: " + meta2["reasoning"]}
        if choice is None:
            choice, meta = Policy._heuristic(cands)
    record = ActionRecord(action_id=choice["action_id"], tool=choice["tool"], args=choice["args"], chosen_by=meta["chosen_by"],
                          reasoning=meta["reasoning"], step=step + 1, alternatives_considered=meta.get("alternatives_considered", 0))
    hyp = dict(state.get("current_hypothesis") or {})
    if meta.get("hypothesis_update"):
        hyp["statement"] = meta["hypothesis_update"]
        hyp["updated_at_step"] = step + 1
    action = _log(state, "AdaptiveEvidenceAgent", "decide_action", f"Next action selected: {choice['tool']}",
                  f"[{meta['chosen_by']}] {meta['reasoning'][:300]}", tool=choice["tool"], args={k: v for k, v in choice["args"].items() if k != "alert"},
                  llm_used=meta["chosen_by"] == "llm", latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"last_action": record, "sufficiency": suff, "current_hypothesis": hyp, "agent_log": [action],
            "executed_action_ids": state.get("executed_action_ids", []) + [{"action_id": choice["action_id"]}]}


def execute_tool(state: InvestigationState, ctx: AgentContext) -> dict:
    """Shared executor for evidence / TI (Agent 4) / graph tools; records evidence."""
    t0 = time.perf_counter()
    act = state["last_action"]
    step = state.get("investigation_step", 0) + 1
    args = dict(act["args"])
    if "alert" in args:
        args["alert"] = state["alert"]
    if act["tool"] in GRAPH_TOOLS:
        args.setdefault("investigation_id", state["investigation_id"])
    res = ctx.tools.execute(act["tool"], args)
    budget = dict(state["budget"])
    budget["steps_used"] += 1
    budget["db_queries"] += 1 if act["tool"] in EVIDENCE_TOOLS else 0
    budget["events_retrieved"] += res.get("count", 0)
    if act["tool"] in TI_TOOLS and act["tool"] != "map_attack_to_mitre":
        budget["ti_lookups_used"] += 1

    seen = set(state.get("seen_record_ids", []))
    record_ids = [r["_id"] for r in res.get("records", []) if "_id" in r]
    novel = [i for i in record_ids if i not in seen]
    ev_id = new_id("evd")
    summary_bits = []
    s = res.get("summary") or {}
    if res["status"] in ("empty", "no_source"):
        summary_bits.append("no matching records" if res["status"] == "empty" else res.get("note", "no source"))
    if s.get("attack_types"):
        summary_bits.append("predicted types: " + ", ".join(f"{k}×{v}" for k, v in sorted(s["attack_types"].items(), key=lambda kv: -kv[1])[:5]))
    if s.get("distinct_count") is not None and res.get("buckets") is not None:
        summary_bits.append(f"{s['distinct_count']} distinct {s.get('group_by')} values; top: " + ", ".join(f"{b['key']}×{b['count']}" for b in res["buckets"][:4]))
    if s.get("destination_ips"):
        summary_bits.append(f"{len(s['destination_ips'])} destination(s)")
    if s.get("alert_ids"):
        summary_bits.append(f"{len(s['alert_ids'])} related alert(s): " + ", ".join(sorted(s['attack_types'])[:4]))
    if res.get("ti"):
        n = res["ti"].get("normalized") or {}
        summary_bits.append(f"{res['ti']['provider']} status={res['ti']['status']}" + (f" verdict={n.get('verdict')}" if n.get("verdict") else "") + (f" ({res['ti'].get('note')})" if res["ti"].get("note") else ""))
    if res.get("mappings"):
        summary_bits.append("ATT&CK: " + ", ".join(f"{m['technique_id']} {m['name']}" for m in res["mappings"][:3]))
    if res.get("truncated"):
        summary_bits.append(f"truncated to {res['count']} of {res['total_matched']} (MAX_EVENTS_PER_QUERY)")
    relevance = "empty" if res["status"] in ("empty", "no_source", "not_configured", "private_address", "unavailable") else "contextual"
    if s.get("attack_types") and any(k != "Benign" for k in s["attack_types"]):
        relevance = "supporting"
    item = EvidenceItem(evidence_id=ev_id, step=step, tool=act["tool"], args={k: v for k, v in act["args"].items() if k != "alert"},
                        summary="; ".join(summary_bits) or res["status"], record_ids=record_ids[:ctx.settings.max_events_per_query], record_count=res.get("count", 0),
                        total_matched=res.get("total_matched", 0), truncated=bool(res.get("truncated")),
                        time_range={"start": s.get("first_seen"), "end": s.get("last_seen")} if s.get("first_seen") else (res.get("window") or {}),
                        attack_types=s.get("attack_types") or {}, entities_found=(s.get("source_ips") or []) + (s.get("destination_ips") or []),
                        relevance=relevance, provenance={**(res.get("provenance") or {}), "status": res["status"], "query_digest": res.get("query_digest")},
                        latency_ms=res.get("wall_ms", 0.0),
                        novelty=len(novel) + (len(s.get("alert_ids", [])) if s.get("alert_ids") else 0) + (1 if res.get("mappings") or res.get("ti") else 0)
                        + (len(res["buckets"]) if res.get("buckets") else 0))
    if res.get("buckets") is not None:
        item["buckets"] = res["buckets"][:20]
    if res.get("ti"):
        item["ti"] = {k: v for k, v in res["ti"].items() if k in ("provider", "status", "normalized", "note", "fetched_at", "indicator", "type")}
    if res.get("mappings"):
        item["mappings"] = res["mappings"]
    if res.get("records") and act["tool"] == "search_alerts":
        item["alerts"] = [{k: a.get(k) for k in ("_id", "attack_type", "category", "severity", "source_ip", "destination_ips", "first_seen", "last_seen", "event_count")} for a in res["records"][:20]]
    tool_call = ToolCall(step=step, tool=act["tool"], args=item["args"], status=res["status"], count=res.get("count", 0), total_matched=res.get("total_matched", 0),
                         latency_ms=res.get("wall_ms", 0.0), query_digest=res.get("query_digest"), evidence_id=ev_id)
    ti_update = dict(state.get("threat_intelligence", {}))
    mitre_update = list(state.get("mitre_mappings", []))
    if res.get("ti"):
        ind = res["ti"]["indicator"]
        ti_update.setdefault(ind, {})
        ti_update[ind][res["ti"]["provider"]] = {k: v for k, v in res["ti"].items() if k in ("status", "normalized", "note", "fetched_at", "type")}
        ti_update[ind]["status"] = res["ti"]["status"]
    if res.get("mappings"):
        have = {(m["attack_type"], m["technique_id"]) for m in mitre_update}
        mitre_update += [m for m in res["mappings"] if (m["attack_type"], m["technique_id"]) not in have]
    last = {**{k: v for k, v in res.items() if k != "records"}, "records": res.get("records", []), "evidence_id": ev_id, "record_ids": record_ids}
    agent_name = "ThreatIntelligenceAgent" if act["tool"] in TI_TOOLS else ("KnowledgeGraphAgent" if act["tool"] in GRAPH_TOOLS else "AdaptiveEvidenceAgent")
    action = _log(state, agent_name, "execute_tool", f"Evidence retrieved via {act['tool']}", item["summary"][:300], tool=act["tool"], args=item["args"],
                  evidence_ids=[ev_id], latency_ms=(time.perf_counter() - t0) * 1000, status=res["status"])
    action["step"] = step
    ctx.emit(action)
    return {"evidence": [item], "tool_history": [tool_call], "last_tool_result": last, "budget": budget, "investigation_step": step,
            "seen_record_ids": list(seen | set(record_ids))[:20000], "threat_intelligence": ti_update, "mitre_mappings": mitre_update, "agent_log": [action]}


def reassess(state: InvestigationState, ctx: AgentContext) -> dict:
    """Update the hypothesis from the evidence discovered so far (LLM or rules)."""
    t0 = time.perf_counter()
    hyp = dict(state.get("current_hypothesis") or {})
    alert = state["alert"]
    # deterministic: stages = attack types performed by the same source, ordered by first_seen
    sg = ctx.graph.get_subgraph(state["investigation_id"], limit=2000)
    src_key = f"IP:{alert['source_ip']}"
    attack_nodes = {n["key"]: n for n in sg["nodes"] if n["label"] == "Attack"}
    performed = [attack_nodes[e["target"]] for e in sg["edges"] if e["type"] == "PERFORMS" and e["source"] == src_key and e["target"] in attack_nodes]
    performed = [n for n in performed if n["properties"].get("first_seen")]
    performed.sort(key=lambda n: n["properties"]["first_seen"])
    stages: List[str] = []
    for n in performed:
        t = n["properties"].get("attack_type")
        if t and t not in stages:
            stages.append(t)
    if not stages:
        stages = [alert["attack_type"]]
    supporting = [e["evidence_id"] for e in state.get("evidence", []) if e.get("relevance") == "supporting"]
    contextual = [e["evidence_id"] for e in state.get("evidence", []) if e.get("relevance") == "contextual"]
    other_sources = set()
    for e in state.get("evidence", []):
        if e["tool"] == "get_related_events" and e["args"].get("strategy") == "same_target":
            other_sources.update(x for x in e.get("entities_found", []) if x not in alert.get("destination_ips", []) and x != alert["source_ip"])
    conf = float(hyp.get("confidence", 0.5))
    conf = min(0.95, conf + 0.04 * len(supporting) + 0.01 * len(contextual))
    if len(stages) > 1:
        seq = " → ".join(stages)
        statement = (f"Multi-stage activity from {alert['source_ip']}: {seq}. The alerted {alert['attack_type']} is stage "
                     f"{stages.index(alert['attack_type']) + 1 if alert['attack_type'] in stages else '?'} of {len(stages)}; ordering is derived from flow timestamps "
                     f"(OCCURS_BEFORE relationships). Each stage is supported by flow-level behavioral evidence of the labelled class only.")
    else:
        statement = hyp.get("statement", "")
        if alert["category"] in ("DDoS", "DoS") and other_sources:
            statement = f"{alert['attack_type']} against {', '.join(alert.get('destination_ips', [])[:3])}; {len(other_sources)} additional source(s) hit the same target in the window, consistent with distributed activity. " + statement
    llm_used = False
    if ctx.policy_mode == "llm" and ctx.llm and ctx.llm.available and state["budget"]["llm_calls_used"] < state["budget"]["max_llm_calls"] \
            and state.get("last_tool_result", {}).get("status") in ("ok", "truncated"):
        prompt = json.dumps({
            "previous_hypothesis": {k: hyp.get(k) for k in ("statement", "confidence", "stages")},
            "derived_stages_from_graph": stages,
            "new_evidence": {k: state["evidence"][-1].get(k) for k in ("tool", "summary", "attack_types", "record_count", "total_matched")} if state.get("evidence") else None,
            "all_evidence_summaries": [{"id": e["evidence_id"], "tool": e["tool"], "summary": e["summary"][:150]} for e in state.get("evidence", [])[-8:]],
            "instruction": "Re-state the hypothesis in <=3 sentences using only these facts; keep the stage list consistent with derived_stages_from_graph (you may not add stages); give confidence in [0,1]; list contradictions if any.",
        }, default=str)
        resp = ctx.llm.generate_json("You are the Adaptive Evidence Collection Agent reassessing an investigation hypothesis. JSON only. Never invent evidence.", prompt, schema=REASSESS_SCHEMA, max_output_tokens=500)
        state["budget"]["llm_calls_used"] += 1
        if resp and resp.get("statement"):
            statement = str(resp["statement"])[:1200]
            conf = float(min(max(resp.get("confidence", conf), 0.05), 0.95))
            llm_used = True
            if resp.get("contradictions"):
                hyp["contradictions"] = [str(c)[:200] for c in resp["contradictions"]][:3]
    hyp.update({"statement": statement, "confidence": round(conf, 3), "stages": stages, "supporting_evidence_ids": supporting,
                "contradicting_evidence_ids": hyp.get("contradicting_evidence_ids", []), "updated_at_step": state.get("investigation_step", 0),
                "category": alert["category"], "attack_type": alert["attack_type"]})
    if len(stages) > 1:
        hyp["category"] = "Multi-stage"
    action = _log(state, "AdaptiveEvidenceAgent", "reassess", "Hypothesis reassessed",
                  f"confidence {conf:.2f}; stages: {' → '.join(stages)}", llm_used=llm_used, latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"current_hypothesis": hyp, "confidence": round(conf, 3), "agent_log": [action]}


# =============================================================================
# Agent 7 — Attack Reconstruction Agent (deterministic)
# =============================================================================
def chain_start_for(stages: List[dict]) -> Optional[str]:
    return stages[0]["first_seen"] if stages else None


def reconstruct(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    inv, alert = state["investigation_id"], state["alert"]
    sg = ctx.graph.get_subgraph(inv, limit=3000)
    nodes = {n["key"]: n for n in sg["nodes"]}
    attacks = [n for n in sg["nodes"] if n["label"] == "Attack" and n["properties"].get("first_seen")]
    perf: Dict[str, List[str]] = {}
    targets: Dict[str, List[str]] = {}
    supported: Dict[str, List[str]] = {}
    techniques: Dict[str, List[dict]] = {}
    for e in sg["edges"]:
        if e["type"] == "PERFORMS":
            perf.setdefault(e["target"], []).append(e["source"].split(":", 1)[1])
        elif e["type"] == "TARGETS":
            targets.setdefault(e["source"], []).append(e["target"].split(":", 1)[1])
        elif e["type"] == "SUPPORTED_BY":
            supported.setdefault(e["source"], []).append(e["target"].split(":", 1)[1])
        elif e["type"] == "MAPS_TO":
            t = nodes.get(e["target"], {}).get("properties", {})
            techniques.setdefault(e["source"], []).append({"technique_id": t.get("technique_id"), "name": t.get("name"), "confidence": e.get("mapping_confidence")})
    # edge evidence ids per attack node
    edge_ev: Dict[str, List[str]] = {}
    for e in sg["edges"]:
        for k in (e["source"], e["target"]):
            if k.startswith("Attack:"):
                edge_ev.setdefault(k, [])
                for i in (e.get("evidence_ids") or []):
                    if i not in edge_ev[k] and len(edge_ev[k]) < 50:
                        edge_ev[k].append(i)
    attacks.sort(key=lambda n: n["properties"]["first_seen"])
    src = alert["source_ip"]
    alert_targets = set(alert.get("destination_ips", []))

    # Stage selection rule (deterministic):
    #   * chain stages   = Attack nodes PERFORMED by the alert source (ordered by first_seen)
    #   * co-sources     = other sources performing the SAME category of flood against an alert target (distributed check)
    #   * other activity = anything else seen against the alert targets — reported as context, never as a chain stage
    chain_nodes, co_sources, other_activity = [], {}, []
    for n in attacks:
        performers = set(perf.get(n["key"], []))
        tg = set(targets.get(n["key"], []))
        p = n["properties"]
        if src in performers:
            chain_nodes.append(n)
        elif alert["category"] in ("DDoS", "DoS") and p.get("category") in ("DDoS", "DoS") and tg & alert_targets:
            for ip in performers:
                co_sources.setdefault(ip, {"source_ip": ip, "attack_types": [], "event_count": 0, "evidence_ids": []})
                co_sources[ip]["attack_types"].append(p.get("attack_type"))
                co_sources[ip]["event_count"] += p.get("event_count") or 0
                co_sources[ip]["evidence_ids"] = (co_sources[ip]["evidence_ids"] + edge_ev.get(n["key"], []))[:20]
        elif tg & alert_targets:
            other_activity.append({"attack_type": p.get("attack_type"), "category": p.get("category"), "sources": sorted(performers), "targets": sorted(tg),
                                   "first_seen": p.get("first_seen"), "last_seen": p.get("last_seen"), "event_count": p.get("event_count"),
                                   "evidence_ids": edge_ev.get(n["key"], [])[:20], "node_key": n["key"]})
    timeline = []
    stages = []
    for idx, n in enumerate(chain_nodes, 1):
        p = n["properties"]
        ev_ids = edge_ev.get(n["key"], []) or n.get("evidence_ids", [])
        stage = {
            "stage": idx, "attack_type": p.get("attack_type"), "category": p.get("category"), "first_seen": p.get("first_seen"), "last_seen": p.get("last_seen"),
            "event_count": p.get("event_count"), "confidence": p.get("confidence"), "sources": sorted(set(perf.get(n["key"], []))), "targets": sorted(set(targets.get(n["key"], []))),
            "node_key": n["key"], "evidence_ids": ev_ids[:50], "evidence_set_ids": supported.get(n["key"], []),
            "techniques": techniques.get(n["key"], []), "is_alert_stage": p.get("attack_type") == alert["attack_type"] and src in perf.get(n["key"], []),
            "alert_id": p.get("alert_id"),
            # support level: isolated 1–2 flow classifications are reported but flagged (possible model misclassification)
            "support": "strong" if (p.get("event_count") or 0) >= 5 else ("moderate" if (p.get("event_count") or 0) >= 3 else "weak"),
        }
        stages.append(stage)
        timeline.append({"time": p.get("first_seen"), "end": p.get("last_seen"), "title": f"{p.get('attack_type')} ({p.get('event_count')} flows)",
                         "type": "attack_stage", "stage": idx, "evidence_ids": ev_ids[:50], "node_key": n["key"], "sources": stage["sources"], "targets": stage["targets"]})
    # add evidence retrievals + TI to the timeline (investigation-side events are separate type)
    for e in state.get("evidence", []):
        if e.get("time_range", {}).get("start") and e.get("record_count"):
            timeline.append({"time": e["time_range"]["start"], "end": e["time_range"].get("end"), "title": f"Evidence: {e['tool']} ({e['record_count']} records)",
                             "type": "evidence", "evidence_ids": [e["evidence_id"]], "record_ids": e["record_ids"][:20]})
    timeline.sort(key=lambda x: x["time"] or "")
    relationships = []
    for i in range(len(stages) - 1):
        a, b = stages[i], stages[i + 1]
        gap = (parse_dt(b["first_seen"]) - parse_dt(a["last_seen"])).total_seconds() if a.get("last_seen") and b.get("first_seen") else None
        shared_src = set(a["sources"]) & set(b["sources"])
        shared_tgt = set(a["targets"]) & set(b["targets"])
        # stages are ordered by first_seen; a negative gap means the two clusters overlap in time
        temporal = None if gap is None else ("sequential" if gap >= 0 else "overlapping")
        relationships.append({"from_stage": a["stage"], "to_stage": b["stage"], "type": "OCCURS_BEFORE",
                              "gap_seconds": None if gap is None else max(gap, 0.0),
                              "overlap_seconds": None if gap is None else max(-gap, 0.0),
                              "temporal_relation": temporal,
                              "shared_sources": sorted(shared_src), "shared_targets": sorted(shared_tgt),
                              "link_strength": "strong" if shared_src and shared_tgt else ("moderate" if shared_src or shared_tgt else "weak"),
                              "evidence_ids": (a["evidence_ids"][:5] + b["evidence_ids"][:5])})
    unsupported = []
    if len(stages) <= 1:
        unsupported.append("No earlier or later stages were found in the retrieved evidence; the incident is reconstructed as a single-stage event (no kill chain is forced).")
    if other_activity:
        unsupported.append(f"{len(other_activity)} other attack-type cluster(s) from different sources were observed against the same target(s); they are reported as context, not attributed to {src}.")
    for r in relationships:
        if r["link_strength"] == "weak":
            unsupported.append(f"Stages {r['from_stage']}→{r['to_stage']} share neither source nor target; the temporal order alone does not establish causality.")
    weak = [st for st in stages if st["support"] == "weak"]
    if weak:
        unsupported.append("Low-support stage(s) " + ", ".join(f"{st['stage']} {st['attack_type']} ({st['event_count']} flow)" for st in weak)
                           + ": fewer than 3 flows were classified with this label; this may be a model misclassification and is reported with a weak-support flag rather than asserted as an attack step.")
    if state.get("graph_state", {}).get("truncated"):
        unsupported.append("Graph node budget (MAX_GRAPH_NODES) was reached; some entities were not added.")
    if co_sources:
        timeline.append({"time": chain_start_for(stages), "title": f"{len(co_sources)} additional source(s) flooding the same target", "type": "distributed",
                         "evidence_ids": [i for c in co_sources.values() for i in c["evidence_ids"]][:20]})
    chain = {"stages": stages, "timeline": timeline, "relationships": relationships, "unsupported_gaps": unsupported,
             "distributed_sources": sorted(co_sources.values(), key=lambda c: -c["event_count"])[:50],
             "other_activity_on_targets": sorted(other_activity, key=lambda o: o["first_seen"] or "")[:50],
             "stage_count": len(stages), "strong_stage_count": sum(1 for st in stages if st["support"] != "weak"),
             "sources": sorted({s for st in stages for s in st["sources"]}), "targets": sorted({t for st in stages for t in st["targets"]}),
             "chain_start": stages[0]["first_seen"] if stages else None, "chain_end": stages[-1]["last_seen"] if stages else None,
             "method": "deterministic: Attack nodes PERFORMED by the alert source ordered by first_seen; other sources flooding the same target are listed as distributed_sources; other activity on the targets is context only"}
    action = _log(state, "AttackReconstructionAgent", "reconstruct", "Attack chain reconstructed",
                  f"{len(stages)} stage(s): " + " → ".join(s["attack_type"] for s in stages) + (f"; {len(unsupported)} caveat(s)" if unsupported else ""),
                  latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"attack_chain": chain, "agent_log": [action]}


# =============================================================================
# Agent 8 — Attack Story & Report Agent
# =============================================================================
NARRATIVE_SYSTEM = """You are the Attack Story & Report Agent of a SOC investigation system.
Write for a security analyst. STRICT RULES:
1. Use ONLY the facts in the structured input. Never add IPs, counts, times, tools, credentials, files or actions that are not present.
2. Network-flow features are behavioral evidence associated with a labelled attack class; never claim they prove specific actions
   (e.g., never say a password was stolen or a query executed) unless such evidence is explicitly present.
3. Every paragraph must reference evidence ids in square brackets, e.g. [evd_...], taken from the input.
4. Where evidence is missing say exactly: "Insufficient evidence".
5. Output JSON with keys: narrative (string, 3-6 short paragraphs), recommended_actions (array of strings, each grounded in a stage), analyst_summary (1-2 sentences)."""

NARRATIVE_SCHEMA = {"type": "object", "properties": {"narrative": {"type": "string"}, "recommended_actions": {"type": "array", "items": {"type": "string"}},
                                                     "analyst_summary": {"type": "string"}}, "required": ["narrative", "recommended_actions", "analyst_summary"]}

GENERIC_ACTIONS = {
    "DDoS": ["Apply rate limiting / upstream filtering for the flood protocol at the gateway serving the targeted device.",
             "Validate service availability of the targeted device and review its exposure to the source network."],
    "DoS": ["Block or rate-limit the single source IP at the perimeter and confirm the targeted service has recovered.",
            "Check whether the source performed reconnaissance earlier (precursor evidence) and monitor for repetition."],
    "Reconnaissance": ["Monitor the source for follow-on activity against the scanned devices; scanning frequently precedes exploitation.",
                       "Review exposed services on the scanned devices and close unnecessary ports."],
    "Web-Based": ["Inspect the web-facing device's application logs for requests from the source in the alert window (not available from flow data).",
                  "Restrict management/web interfaces of the affected IoT device to trusted networks."],
    "Brute Force": ["Verify authentication logs on the targeted device for the alert window (flow data cannot confirm success or failure).",
                    "Enforce strong credentials / lockout on SSH/Telnet services of the device and restrict access."],
    "Spoofing": ["Enable dynamic ARP inspection / DHCP snooping on the affected segment and validate DNS resolver configuration of the devices.",
                 "Check the devices for signs of traffic interception (not available from flow data)."],
}


def _claim(text: str, evidence_ids: List[str], confidence: str = "measured") -> dict:
    return {"claim_id": new_id("clm"), "text": text, "evidence_ids": evidence_ids[:20], "confidence": confidence, "validated": bool(evidence_ids)}


def narrate_and_report(state: InvestigationState, ctx: AgentContext) -> dict:
    t0 = time.perf_counter()
    alert, chain = state["alert"], state.get("attack_chain") or {"stages": [], "relationships": [], "unsupported_gaps": []}
    hyp = state.get("current_hypothesis") or {}
    evidence = state.get("evidence", [])
    ev_by_id = {e["evidence_id"]: e for e in evidence}
    alert_ev = alert.get("event_ids_sample", [])[:20]

    # ---- deterministic claims (each with evidence ids)
    claims = [_claim(f"Alert {alert['_id']}: {alert['event_count']} flows from {alert['source_ip']} predicted as {alert['attack_type']} "
                     f"(mean confidence {alert['confidence_mean']:.2f}) between {alert['first_seen']} and {alert['last_seen']}.", alert_ev)]
    for st in chain["stages"]:
        claims.append(_claim(f"Stage {st['stage']}: {st['attack_type']} from {', '.join(st['sources'])} against {', '.join(st['targets'][:3])} "
                             f"({st['event_count']} flows, {st['first_seen']} → {st['last_seen']}).", st["evidence_ids"] or st.get("evidence_set_ids", [])))
    for r in chain["relationships"]:
        if r.get("temporal_relation") == "overlapping":
            when = (f"Stage {r['from_stage']} started before stage {r['to_stage']} but the two overlapped in time "
                    f"(overlap {r['overlap_seconds']:.0f}s; order is by first-seen timestamp)")
        elif r.get("gap_seconds") is None:
            when = f"Stage {r['from_stage']} is ordered before stage {r['to_stage']} (gap not measurable)"
        else:
            when = f"Stage {r['from_stage']} preceded stage {r['to_stage']} by {r['gap_seconds']:.0f}s"
        claims.append(_claim(f"{when} ({r['link_strength']} link: shared sources {r['shared_sources']}, shared targets {r['shared_targets']}).",
                             r["evidence_ids"], "inferred" if r["link_strength"] != "strong" else "measured"))
    for e in evidence:
        if e.get("relevance") == "supporting":
            claims.append(_claim(f"{e['tool']} returned {e['record_count']} records ({e['summary'][:140]}).", [e["evidence_id"]]))
    ti = state.get("threat_intelligence", {})
    ti_rows = []
    for ind, providers in ti.items():
        for prov, d in providers.items():
            if prov == "status" or not isinstance(d, dict):
                continue
            ti_rows.append({"indicator": ind, "provider": prov, "status": d.get("status"), "normalized": d.get("normalized"), "note": d.get("note")})
    for row in ti_rows:
        if row["status"] == "ok":
            claims.append(_claim(f"{row['provider']} report for {row['indicator']}: verdict {row['normalized'].get('verdict')}.", [e["evidence_id"] for e in evidence if e.get("ti", {}).get("indicator") == row["indicator"]]))
    mitre = state.get("mitre_mappings", [])
    if chain.get("distributed_sources"):
        ds = chain["distributed_sources"]
        claims.append(_claim(f"{len(ds)} additional source(s) ({', '.join(d['source_ip'] for d in ds[:5])}{'…' if len(ds) > 5 else ''}) sent flood-class flows to the same target during the window; the activity is consistent with a distributed attack.",
                             [i for d in ds for i in d["evidence_ids"]][:20]))

    # ---- severity from evidence
    sev_order = ["info", "low", "medium", "high", "critical"]
    sev = alert["severity"]
    sev_reason = list(alert.get("severity_rationale", []))
    strong_stages = chain.get("strong_stage_count", chain["stage_count"])
    if strong_stages >= 2 and sev_order.index(sev) < 4:
        sev = sev_order[min(sev_order.index(sev) + 1, 4)]
        sev_reason.append(f"multi-stage chain ({strong_stages} supported stages) → +1")
    if len(chain.get("distributed_sources", [])) >= 2 and sev_order.index(sev) < 4:
        sev = sev_order[sev_order.index(sev) + 1]
        sev_reason.append(f"{len(chain['distributed_sources'])} additional sources flooding the same target (distributed) → +1")
    if any(r["status"] == "ok" and (r["normalized"] or {}).get("verdict") in ("malicious", "reported_in_pulses") for r in ti_rows) and sev_order.index(sev) < 4:
        sev = sev_order[sev_order.index(sev) + 1]
        sev_reason.append("external threat-intelligence verdict malicious/reported → +1")

    # ---- limitations
    limitations = [
        "Entity and time context (IP addresses, devices, timestamps) is synthesized for CICIoT2023 flows; feature values and attack labels come from the data source recorded in each event." if alert.get("provenance") == "synthesized" else "Entity context taken from the ingested source.",
        "Flow features are behavioral evidence associated with the labelled class; usernames, commands, payloads, files and process activity are not available from the current evidence.",
    ]
    if alert.get("data_source") == "synthetic_demo":
        limitations.insert(0, "DEMONSTRATION DATA: the flows behind this report are synthetic placeholders generated because no CICIoT2023 files were present in DATASET_DIR. No statement in this report describes the real dataset.")
    limitations += chain.get("unsupported_gaps", [])
    if state.get("termination_reason") in ("max_steps", "timeout", "budget"):
        limitations.append(f"Investigation stopped by safeguard ({state['termination_reason']}); further evidence may exist.")
    empty_tools = sorted({e["tool"] for e in evidence if e.get("relevance") == "empty"})
    if empty_tools:
        limitations.append("Queries with no usable result: " + ", ".join(empty_tools) + ".")
    if not any(r["status"] == "ok" for r in ti_rows):
        limitations.append("No external threat-intelligence data was obtained (provider not configured, indicator private/documentation range, or unavailable).")

    # ---- narrative (LLM or template) with grounding validation
    llm_used, validation = False, {"checked": False}
    narrative, actions, analyst_summary = None, [], None
    if ctx.policy_mode == "llm" and ctx.llm and ctx.llm.available and state["budget"]["llm_calls_used"] < state["budget"]["max_llm_calls"]:
        payload = {
            "alert": {k: alert.get(k) for k in ("_id", "attack_type", "category", "severity", "source_ip", "destination_ips", "device_ids", "event_count", "confidence_mean", "first_seen", "last_seen")},
            "hypothesis": {k: hyp.get(k) for k in ("statement", "confidence", "stages")},
            "attack_chain": {"stages": [{k: s[k] for k in ("stage", "attack_type", "sources", "targets", "event_count", "first_seen", "last_seen", "evidence_ids")} for s in chain["stages"]],
                             "relationships": chain["relationships"], "unsupported_gaps": chain["unsupported_gaps"]},
            "evidence": [{"id": e["evidence_id"], "tool": e["tool"], "summary": e["summary"][:200], "records": e["record_count"]} for e in evidence[:14]],
            "threat_intelligence": ti_rows[:6],
            "mitre": [{k: m[k] for k in ("attack_type", "technique_id", "name", "confidence")} for m in mitre[:8]],
            "limitations": limitations,
        }
        resp = ctx.llm.generate_json(NARRATIVE_SYSTEM, json.dumps(payload, default=str), schema=NARRATIVE_SCHEMA, temperature=0.3, max_output_tokens=1800)
        state["budget"]["llm_calls_used"] += 1
        if resp and resp.get("narrative"):
            validation = validate_grounding(str(resp["narrative"]), state)
            if validation["passed"]:
                narrative, llm_used = str(resp["narrative"]), True
                actions = [str(a)[:300] for a in resp.get("recommended_actions", [])][:8]
                analyst_summary = str(resp.get("analyst_summary", ""))[:400]
            else:
                log.warning("LLM narrative failed grounding validation: %s", validation)
    if narrative is None:
        narrative = template_narrative(state, chain, hyp, ti_rows, mitre)
    if not actions:
        cats = {alert["category"]} | {s["category"] for s in chain["stages"] if s.get("category")}
        for c in cats:
            actions += GENERIC_ACTIONS.get(c, [])
        actions = actions[:6]
    if not analyst_summary:
        analyst_summary = f"{chain['stage_count']}-stage {'multi-stage incident' if chain['stage_count'] > 1 else alert['attack_type']} from {alert['source_ip']}; severity {sev}; {len(evidence)} evidence items, {sum(1 for c in claims if c['validated'])}/{len(claims)} claims evidence-linked."

    report = {
        "investigation_id": state["investigation_id"], "alert_id": alert["_id"], "generated_at": to_iso(utcnow()),
        "sections": {
            "1_incident_title": _title(chain, alert),
            "2_alert_summary": {k: alert.get(k) for k in ("_id", "attack_type", "category", "predicted_label", "severity", "source_ip", "destination_ips", "device_ids", "protocols", "event_count", "confidence_mean", "first_seen", "last_seen", "model_version")},
            "3_severity": {"level": sev, "rationale": sev_reason},
            "4_affected_entities": [{"key": k, "type": v["type"], "value": v["value"], "role": v["role"]} for k, v in state.get("entities", {}).items()],
            "5_source_destination": {"source_ip": alert["source_ip"], "destination_ips": alert.get("destination_ips", []), "devices": alert.get("device_ids", []),
                                     "distributed_sources": chain.get("distributed_sources", []), "other_activity_on_targets": chain.get("other_activity_on_targets", [])},
            "6_attack_timeline": chain.get("timeline", []),
            "7_attack_chain": {"stages": chain["stages"], "relationships": chain["relationships"], "method": chain.get("method")},
            "8_knowledge_graph_summary": state.get("graph_state", {}),
            "9_behavioral_evidence": alert.get("behavioral_evidence", {}),
            "10_threat_intelligence": {"results": ti_rows, "note": "Actual API results; AI interpretation (if any) is shown separately in the UI."},
            "11_mitre_mapping": mitre,
            "12_supporting_evidence": [{k: e.get(k) for k in ("evidence_id", "step", "tool", "args", "summary", "record_count", "total_matched", "truncated", "relevance", "record_ids")} for e in evidence],
            "13_ai_attack_narrative": {"text": narrative, "generated_by": "gemini" if llm_used else "template (LLM unavailable or narrative failed grounding validation)",
                                       "model": ctx.settings.gemini_model if llm_used else None, "grounding_validation": validation},
            "14_recommended_actions": actions,
            "15_investigation_limitations": limitations,
        },
        "claims": claims,
        "analyst_summary": analyst_summary,
        "hypothesis": hyp,
        "termination_reason": state.get("termination_reason"),
        "metrics": {"steps": state["budget"]["steps_used"], "db_queries": state["budget"]["db_queries"], "events_retrieved": state["budget"]["events_retrieved"],
                    "llm_calls": state["budget"]["llm_calls_used"], "ti_lookups": state["budget"]["ti_lookups_used"], "evidence_items": len(evidence),
                    "claims": len(claims), "claims_validated": sum(1 for c in claims if c["validated"])},
        "llm": {"used": llm_used, "model": ctx.settings.gemini_model if llm_used else None, "policy": ctx.policy_mode},
    }
    action = _log(state, "AttackStoryReportAgent", "narrate_and_report", "Evidence-backed report generated",
                  f"severity {sev}; {len(claims)} claims ({report['metrics']['claims_validated']} evidence-linked); narrative by {'Gemini' if llm_used else 'template'}",
                  llm_used=llm_used, latency_ms=(time.perf_counter() - t0) * 1000)
    ctx.emit(action)
    return {"final_report": report, "agent_log": [action], "status": "completed"}


def validate_grounding(text: str, state: InvestigationState) -> dict:
    """Reject narratives that cite unknown evidence ids or mention IPs absent from the state."""
    import re

    known_ev = {e["evidence_id"] for e in state.get("evidence", [])}
    cited = set(re.findall(r"\bevd_[A-Za-z0-9]+\b", text))
    unknown_ev = sorted(cited - known_ev)
    ips_in_text = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    known_ips = {v["value"] for v in state.get("entities", {}).values() if v["type"] == "IP"} | {state["alert"]["source_ip"]} | set(state["alert"].get("destination_ips", []))
    for e in state.get("evidence", []):
        known_ips.update(e.get("entities_found", []))
    unknown_ips = sorted(ips_in_text - known_ips)
    forbidden = [w for w in ("password was stolen", "credentials were stolen", "exfiltrated", "executed the command", "malware was installed") if w in text.lower()]
    passed = not unknown_ev and not unknown_ips and not forbidden and (len(cited) > 0 or not known_ev)
    return {"checked": True, "passed": passed, "cited_evidence": len(cited), "unknown_evidence_ids": unknown_ev, "unknown_ips": unknown_ips, "forbidden_phrases": forbidden}


def _title(chain: dict, alert: dict) -> str:
    names = [s["attack_type"] for s in chain["stages"] if s.get("support") != "weak"] or [alert["attack_type"]]
    seq = " → ".join(names[:4]) + (f" (+{len(names) - 4} more)" if len(names) > 4 else "")
    return f"{'Multi-stage ' if len(names) > 1 else ''}{seq} from {alert['source_ip']}"


def template_narrative(state: InvestigationState, chain: dict, hyp: dict, ti_rows: List[dict], mitre: List[dict]) -> str:
    alert = state["alert"]
    paras = []
    alert_ev = alert.get("event_ids_sample", [])[:3]
    paras.append(f"At {alert['first_seen']}, {alert['event_count']} network flows from {alert['source_ip']} towards {', '.join(alert.get('destination_ips', [])[:3])} were classified as "
                 f"{alert['attack_type']} ({alert['category']}) with mean model confidence {alert['confidence_mean']:.2f}. The flow-level features "
                 + (", ".join(r['feature'] for r in alert.get('behavioral_evidence', {}).get('top_features', [])[:3]) or "of the flows")
                 + f" provide behavioral evidence associated with the labelled {alert['attack_type']} class [{', '.join(alert_ev) or 'alert events'}].")
    if chain["stage_count"] > 1:
        seq = []
        for s in chain["stages"]:
            seq.append(f"stage {s['stage']} {s['attack_type']} ({s['event_count']} flows{', weak support' if s.get('support') == 'weak' else ''}, {s['first_seen']} → {s['last_seen']}) [{', '.join(s['evidence_ids'][:2]) or 'graph'}]")
        paras.append("Adaptive evidence collection linked the alert to related activity of the same source: " + "; ".join(seq) + ". "
                     "Stage order is derived from flow timestamps; " + "; ".join(f"stages {r['from_stage']}→{r['to_stage']} are a {r['link_strength']} link (shared targets: {', '.join(r['shared_targets']) or 'none'})" for r in chain["relationships"]) + ".")
    else:
        paras.append("Adaptive evidence collection found no earlier or later stages attributable to the source within the retrieved windows; the incident is reported as a single-stage event. "
                     + " ".join(f"[{e['evidence_id']}] {e['tool']}: {e['summary'][:100]}." for e in state.get('evidence', []) if e.get('relevance') == 'supporting')[:600])
    if chain.get("distributed_sources"):
        ds = chain["distributed_sources"]
        paras.append(f"Distributed activity: {len(ds)} other source(s) ({', '.join(d['source_ip'] for d in ds[:5])}{'…' if len(ds) > 5 else ''}) sent {sum(d['event_count'] for d in ds)} flood-class flows to the same target in the retrieved window "
                     f"[{', '.join(sorted({i for d in ds for i in d['evidence_ids']})[:3])}]. Whether these sources are coordinated cannot be established from flow features alone.")
    if chain.get("other_activity_on_targets"):
        oa = chain["other_activity_on_targets"]
        paras.append(f"Other activity on the same target(s) (context, not attributed to {alert['source_ip']}): " + "; ".join(f"{o['attack_type']} from {', '.join(o['sources'][:2])} ({o['event_count']} flows)" for o in oa[:4]) + ".")
    ok_ti = [r for r in ti_rows if r["status"] == "ok"]
    if ok_ti:
        paras.append("Threat intelligence: " + "; ".join(f"{r['provider']} reports {r['indicator']} as {r['normalized'].get('verdict')}" for r in ok_ti) + ".")
    else:
        paras.append("Threat intelligence: Insufficient evidence — no external reputation data was obtained for the source indicator "
                     + ("(documentation/private address range, not sent to providers)." if ti_rows and all(r["status"] == "private_address" for r in ti_rows) else "(provider not configured or unavailable)."))
    if mitre:
        paras.append("ATT&CK context: " + "; ".join(f"{m['attack_type']} ↔ {m['technique_id']} {m['name']} ({m['confidence']} confidence)" for m in mitre[:5]) + ". These are curated class-level associations, not conclusions from individual flows.")
    paras.append("What cannot be concluded: usernames, passwords, commands, payloads, files or process activity — Insufficient evidence from network-flow features alone.")
    return "\n\n".join(paras)
