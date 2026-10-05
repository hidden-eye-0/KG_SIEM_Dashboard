"""Investigation tool registry (architecture review §4).

Every tool returns a `ToolResult` dict with a uniform shape so the agents, the UI and
the evaluation harness can reason about it:

    {tool, args, status: ok|empty|truncated|unavailable|not_configured|error|private_address,
     records, count, total_matched, latency_ms, query_cost, provenance, note, ...}

Limits (MAX_EVENTS_PER_QUERY, MAX_TIME_WINDOW_SECONDS) are enforced by the repository;
the registry additionally records every call so budgets and evaluation counters are exact.
`ground_truth` never leaves the repository layer.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from backend.config import Settings
from backend.services.graph_store import GraphStore
from backend.services.mitre import MitreService
from backend.services.repository import EvidenceRepository
from backend.services.threat_intel import ThreatIntelService
from backend.utils.ids import digest
from backend.utils.timeutil import to_iso

log = logging.getLogger(__name__)

EVIDENCE_TOOLS = {
    "search_security_events", "get_events_by_ip", "get_events_by_time_range", "get_events_by_device",
    "get_related_events", "get_authentication_events", "get_network_events", "get_dns_events",
    "get_firewall_events", "search_alerts", "get_event_aggregates",
}
TI_TOOLS = {"check_virustotal_ip", "check_virustotal_domain", "check_virustotal_hash", "check_otx_indicator", "map_attack_to_mitre"}
GRAPH_TOOLS = {"query_related_nodes", "get_attack_subgraph"}

COST = {  # relative cost hints used by the policy (higher = more expensive)
    "get_event_aggregates": 0.5, "search_alerts": 0.5, "map_attack_to_mitre": 0.2,
    "query_related_nodes": 0.3, "get_attack_subgraph": 0.4,
    "check_virustotal_ip": 2.0, "check_virustotal_domain": 2.0, "check_virustotal_hash": 2.0, "check_otx_indicator": 1.5,
}


@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    fn: Callable[..., Dict[str, Any]]
    requires: List[str] = field(default_factory=list)

    @property
    def cost(self) -> float:
        return COST.get(self.name, 1.0)


def _summarise_events(records: List[dict]) -> Dict[str, Any]:
    attack_types: Dict[str, int] = {}
    srcs, dsts, devs, protos = set(), set(), set(), set()
    first = last = None
    for r in records:
        p = (r.get("prediction") or {})
        at = p.get("attack_type") or "unknown"
        attack_types[at] = attack_types.get(at, 0) + 1
        srcs.add(r.get("source_ip"))
        dsts.add(r.get("destination_ip"))
        if r.get("device_id"):
            devs.add(r["device_id"])
        if r.get("protocol"):
            protos.add(r["protocol"])
        ts = r.get("timestamp")
        if ts is not None:
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
    return {
        "attack_types": attack_types,
        "source_ips": sorted(x for x in srcs if x), "destination_ips": sorted(x for x in dsts if x),
        "device_ids": sorted(devs), "protocols": sorted(protos),
        "first_seen": to_iso(first), "last_seen": to_iso(last),
    }


class ToolRegistry:
    def __init__(self, repo: EvidenceRepository, ti: ThreatIntelService, graph: GraphStore, mitre: MitreService,
                 settings: Settings):
        self.repo, self.ti, self.graph, self.mitre, self.settings = repo, ti, graph, mitre, settings
        self.calls: List[Dict[str, Any]] = []
        self.specs: Dict[str, ToolSpec] = {}
        self._register_all()

    # ------------------------------------------------------------------ registration
    def _reg(self, name: str, category: str, description: str, fn: Callable, requires: Optional[List[str]] = None):
        self.specs[name] = ToolSpec(name, category, description, fn, requires or [])

    def _register_all(self) -> None:
        r = self.repo
        # evidence
        self._reg("search_security_events", "evidence", "Filtered search over the security-event repository", self._ev(lambda a: r.search_security_events(a.get("filters"), a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("get_events_by_ip", "evidence", "Events where the IP is source/destination", self._ev(lambda a: r.get_events_by_ip(a["ip"], a.get("role", "any"), a.get("start"), a.get("end"), a.get("limit"), a.get("exclude_attack_type"))))
        self._reg("get_events_by_time_range", "evidence", "Events in a time window (clamped to MAX_TIME_WINDOW)", self._ev(lambda a: r.get_events_by_time_range(a["start"], a["end"], a.get("filters"), a.get("limit"))))
        self._reg("get_events_by_device", "evidence", "Events targeting a device", self._ev(lambda a: r.get_events_by_device(a["device_id"], a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("get_related_events", "evidence", "Events related to the alert (same_source|same_target|same_pair|follow_on|precursor)", self._ev(lambda a: r.get_related_events(a["alert"], a.get("strategy", "same_source"), a.get("window_seconds", 3600), a.get("limit"))))
        self._reg("get_authentication_events", "evidence", "Flows on authentication protocols (SSH/Telnet indicator) — network evidence only", self._ev(lambda a: r.get_authentication_events(a.get("ip"), a.get("device_id"), a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("get_network_events", "evidence", "Flows for an IP filtered by protocol", self._ev(lambda a: r.get_network_events(a.get("ip"), a.get("protocol"), a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("get_dns_events", "evidence", "Flows with the DNS indicator", self._ev(lambda a: r.get_dns_events(a.get("ip"), a.get("device_id"), a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("get_firewall_events", "evidence", "Firewall log events (returns no_source unless a firewall source is ingested)", self._ev(lambda a: r.get_firewall_events(a.get("ip"), a.get("start"), a.get("end"), a.get("limit"))))
        self._reg("search_alerts", "evidence", "Other alerts sharing source/destination/category", self._alerts)
        self._reg("get_event_aggregates", "evidence", "Counts grouped by a field (no row retrieval)", self._agg)
        # threat intel
        self._reg("check_virustotal_ip", "threat_intel", "VirusTotal IP report (passive)", lambda a: self._ti(self.ti.check_virustotal(a["ip"], "ip")), ["virustotal"])
        self._reg("check_virustotal_domain", "threat_intel", "VirusTotal domain report (passive)", lambda a: self._ti(self.ti.check_virustotal(a["domain"], "domain")), ["virustotal"])
        self._reg("check_virustotal_hash", "threat_intel", "VirusTotal file report (passive)", lambda a: self._ti(self.ti.check_virustotal(a["hash"], "hash")), ["virustotal"])
        self._reg("check_otx_indicator", "threat_intel", "AlienVault OTX indicator (passive)", lambda a: self._ti(self.ti.check_otx(a["indicator"], a.get("type"))), ["otx"])
        self._reg("map_attack_to_mitre", "threat_intel", "Curated ATT&CK mapping for an attack type (verified against local STIX bundle when present)", self._mitre)
        # graph
        self._reg("query_related_nodes", "graph", "Neighbourhood of a graph node", self._related_nodes)
        self._reg("get_attack_subgraph", "graph", "Investigation subgraph", self._subgraph)

    # ------------------------------------------------------------------ wrappers
    def _ev(self, fn: Callable[[dict], dict]) -> Callable[[dict], dict]:
        def wrapped(args: dict) -> dict:
            res = fn(args)
            recs = res["records"]
            status = "empty" if res["count"] == 0 else ("truncated" if res.get("truncated") else "ok")
            if res.get("no_source"):
                status = "no_source"
            out = {
                "status": status, "records": recs, "count": res["count"], "total_matched": res["total_matched"],
                "truncated": bool(res.get("truncated")), "latency_ms": res["latency_ms"],
                "window": {k: (to_iso(v) if hasattr(v, "isoformat") else v) for k, v in (res.get("window") or {}).items()},
                "summary": _summarise_events(recs),
                "provenance": {"collection": "security_events", "query_digest": digest(res.get("query"))},
                "query_cost": 1,
            }
            if status == "no_source":
                out["note"] = "No firewall log source has been ingested; not available from the current evidence."
            return out
        return wrapped

    def _alerts(self, a: dict) -> dict:
        res = self.repo.search_alerts(a.get("source_ip"), a.get("destination_ip"), a.get("category"),
                                      a.get("exclude_alert_id"), a.get("start"), a.get("end"), a.get("limit", 50))
        recs = res["records"]
        return {"status": "ok" if recs else "empty", "records": recs, "count": len(recs), "total_matched": res["total_matched"],
                "truncated": res["total_matched"] > len(recs), "latency_ms": res["latency_ms"],
                "summary": {"alert_ids": [r["_id"] for r in recs], "attack_types": {r["attack_type"]: 1 for r in recs},
                            "categories": sorted({r["category"] for r in recs})},
                "provenance": {"collection": "alerts", "query_digest": digest(res["query"])}, "query_cost": 1}

    def _agg(self, a: dict) -> dict:
        res = self.repo.get_event_aggregates(a["group_by"], a.get("filters"), a.get("start"), a.get("end"), a.get("top", 20))
        buckets = [{**b, "first_seen": to_iso(b["first_seen"]), "last_seen": to_iso(b["last_seen"])} for b in res["buckets"]]
        return {"status": "ok" if buckets else "empty", "records": [], "count": 0, "total_matched": sum(b["count"] for b in buckets),
                "truncated": False, "latency_ms": res["latency_ms"], "buckets": buckets, "distinct_count": res["distinct_count"],
                "summary": {"group_by": a["group_by"], "distinct_count": res["distinct_count"], "top": buckets[:5]},
                "provenance": {"collection": "security_events", "aggregation": True, "query_digest": digest(res["query"])}, "query_cost": 1}

    def _ti(self, doc: dict) -> dict:
        d = {k: v for k, v in doc.items() if k != "_id"}
        return {"status": d["status"], "records": [], "count": 0, "total_matched": 0, "truncated": False,
                "latency_ms": 0.0, "ti": d, "summary": {"provider": d["provider"], "status": d["status"], **(d.get("normalized") or {})},
                "provenance": {"provider": d["provider"], "cache_hit": d.get("cache_hit", False)}, "query_cost": 0, "note": d.get("note")}

    def _mitre(self, a: dict) -> dict:
        types = a.get("attack_types") or ([a["attack_type"]] if a.get("attack_type") else [])
        maps = [m for t in types for m in self.mitre.map_attack_type(t)]
        return {"status": "ok" if maps else "empty", "records": [], "count": len(maps), "total_matched": len(maps), "truncated": False,
                "latency_ms": 0.0, "mappings": maps, "summary": {"technique_ids": [m["technique_id"] for m in maps]},
                "provenance": {"source": "curated_mapping", "bundle_loaded": self.mitre.bundle_loaded}, "query_cost": 0}

    def _related_nodes(self, a: dict) -> dict:
        t0 = time.perf_counter()
        res = self.graph.related_nodes(a["key"], a.get("investigation_id"), a.get("depth", 1))
        return {"status": "ok" if res["nodes"] else "empty", "records": [], "count": len(res["nodes"]), "total_matched": len(res["nodes"]),
                "truncated": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "graph": res,
                "summary": {"neighbour_count": len(res["nodes"])}, "provenance": {"graph_backend": self.graph.backend}, "query_cost": 0}

    def _subgraph(self, a: dict) -> dict:
        t0 = time.perf_counter()
        res = self.graph.get_subgraph(a["investigation_id"], a.get("types"), a.get("start"), a.get("end"), a.get("limit", 1000))
        return {"status": "ok" if res["nodes"] else "empty", "records": [], "count": len(res["nodes"]), "total_matched": len(res["nodes"]),
                "truncated": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "graph": res,
                "summary": {"nodes": len(res["nodes"]), "edges": len(res["edges"])}, "provenance": {"graph_backend": self.graph.backend}, "query_cost": 0}

    # ------------------------------------------------------------------ execution
    def execute(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        spec = self.specs.get(tool)
        t0 = time.perf_counter()
        if spec is None:
            result = {"status": "error", "records": [], "count": 0, "total_matched": 0, "truncated": False, "latency_ms": 0.0,
                      "note": f"unknown tool {tool}", "summary": {}, "provenance": {}, "query_cost": 0}
        else:
            try:
                result = spec.fn(args)
            except Exception as exc:
                log.exception("tool %s failed", tool)
                result = {"status": "error", "records": [], "count": 0, "total_matched": 0, "truncated": False, "latency_ms": 0.0,
                          "note": f"{type(exc).__name__}: {exc}", "summary": {}, "provenance": {}, "query_cost": 0}
        result["tool"] = tool
        result["args"] = {k: v for k, v in args.items() if k != "alert"} | ({"alert_id": args["alert"]["_id"]} if "alert" in args else {})
        result["wall_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        result["query_digest"] = digest({"tool": tool, "args": result["args"]})
        self.calls.append({"tool": tool, "args": result["args"], "status": result["status"], "count": result["count"],
                           "total_matched": result["total_matched"], "latency_ms": result["wall_ms"], "query_digest": result["query_digest"]})
        return result

    def describe(self) -> List[Dict[str, Any]]:
        return [{"name": s.name, "category": s.category, "description": s.description, "requires": s.requires, "cost": s.cost}
                for s in self.specs.values()]
