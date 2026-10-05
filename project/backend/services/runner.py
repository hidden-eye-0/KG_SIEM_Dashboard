"""Investigation runner: creates investigations, executes the LangGraph loop in a worker
thread, persists state after every node, and fans agent actions out to SSE subscribers.
"""
from __future__ import annotations

import logging
import queue
import threading
import traceback
from typing import Any, Dict, List, Optional

from backend.agents.agents import AgentContext
from backend.agents.graph import build_investigation_graph
from backend.agents.state import InvestigationState
from backend.config import Settings
from backend.services.gemini import GeminiClient
from backend.services.graph_store import GraphStore
from backend.services.mitre import MitreService
from backend.services.mongo import DocumentStore
from backend.services.repository import EvidenceRepository
from backend.services.threat_intel import ThreatIntelService
from backend.tools.registry import ToolRegistry
from backend.utils.ids import new_id
from backend.utils.timeutil import to_iso, utcnow

log = logging.getLogger(__name__)


class EventBus:
    """Per-investigation fan-out of agent actions to SSE subscribers."""

    def __init__(self):
        self._subs: Dict[str, List[queue.Queue]] = {}
        self._lock = threading.Lock()

    def subscribe(self, inv_id: str) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.setdefault(inv_id, []).append(q)
        return q

    def unsubscribe(self, inv_id: str, q: queue.Queue) -> None:
        with self._lock:
            if inv_id in self._subs and q in self._subs[inv_id]:
                self._subs[inv_id].remove(q)

    def publish(self, inv_id: str, event: Dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs.get(inv_id, []))
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:  # slow consumer: drop
                pass


def _serialisable(obj: Any) -> Any:
    """Make a state snapshot JSON/BSON safe (datetimes → iso, tuples → lists)."""
    import datetime as _dt

    if isinstance(obj, dict):
        return {str(k): _serialisable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_serialisable(v) for v in obj]
    if isinstance(obj, _dt.datetime):
        return to_iso(obj)
    if isinstance(obj, float) and (obj != obj):
        return None
    return obj


class InvestigationRunner:
    def __init__(self, settings: Settings, store: DocumentStore, graph: GraphStore, llm: GeminiClient, mitre: MitreService):
        self.settings, self.store, self.graph, self.llm, self.mitre = settings, store, graph, llm, mitre
        self.bus = EventBus()
        self.repo = EvidenceRepository(store, settings)
        self.ti = ThreatIntelService(settings, store)
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_flags: Dict[str, threading.Event] = {}

    # ------------------------------------------------------------------ profiles
    def _profiles_by_type(self) -> Dict[str, dict]:
        out = {}
        for p in self.store["behavior_profiles"].find({"kind": {"$ne": "global"}}):
            out[p["attack_type"]] = p
        return out

    # ------------------------------------------------------------------ create
    def create(self, alert_id: str, mode: str = "adaptive", policy: Optional[str] = None) -> dict:
        alert = self.store["alerts"].find_one({"_id": alert_id})
        if not alert:
            raise KeyError(alert_id)
        inv_id = new_id("inv")
        policy_mode = "fixed" if mode == "baseline" else (policy or self.settings.effective_policy)
        if policy_mode == "llm" and not (self.llm and self.llm.available):
            policy_mode = "heuristic"
        doc = {
            "_id": inv_id, "alert_id": alert_id, "mode": mode, "policy": policy_mode, "status": "created",
            "created_at": utcnow(), "started_at": None, "finished_at": None,
            "config": {"budget": self.settings.public_dict()["budget"], "gemini_model": self.settings.gemini_model,
                       "prompt_version": "2026-09-05.1", "seed": self.settings.random_seed, "graph_backend": self.graph.backend,
                       "store_backend": self.store.backend},
            "state": None, "steps": [], "metrics": {},
            "alert_summary": {k: alert.get(k) for k in ("attack_type", "category", "severity", "source_ip", "destination_ips", "first_seen", "last_seen", "event_count")},
        }
        self.store["investigations"].insert_one(doc)
        self.store["alerts"].update_one({"_id": alert_id}, {"$push": {"investigation_ids": inv_id}, "$set": {"status": "investigating"}})
        return doc

    # ------------------------------------------------------------------ start
    def start(self, inv_id: str) -> dict:
        doc = self.store["investigations"].find_one({"_id": inv_id})
        if not doc:
            raise KeyError(inv_id)
        if doc["status"] == "running":
            return doc
        stop_flag = threading.Event()
        self._stop_flags[inv_id] = stop_flag
        t = threading.Thread(target=self._run, args=(inv_id, stop_flag), name=f"inv-{inv_id}", daemon=True)
        self._threads[inv_id] = t
        self.store["investigations"].update_one({"_id": inv_id}, {"$set": {"status": "running", "started_at": utcnow()}})
        t.start()
        return self.store["investigations"].find_one({"_id": inv_id})

    def stop(self, inv_id: str) -> None:
        flag = self._stop_flags.get(inv_id)
        if flag:
            flag.set()

    def run_sync(self, inv_id: str) -> dict:
        """Blocking execution (used by the evaluation harness and tests)."""
        self.store["investigations"].update_one({"_id": inv_id}, {"$set": {"status": "running", "started_at": utcnow()}})
        self._run(inv_id, threading.Event())
        return self.store["investigations"].find_one({"_id": inv_id})

    # ------------------------------------------------------------------ core
    def _initial_state(self, doc: dict, alert: dict) -> InvestigationState:
        b = self.settings
        alert_view = _serialisable({k: v for k, v in alert.items() if k not in ("ground_truth",)})
        return InvestigationState(
            investigation_id=doc["_id"], alert_id=alert["_id"], mode=doc["mode"], policy=doc["policy"], alert=alert_view,
            current_hypothesis={}, entities={}, evidence=[], missing_evidence=[], candidate_actions=[], last_action=None, last_tool_result=None,
            tool_history=[], threat_intelligence={}, mitre_mappings=[], graph_state={"node_count": 0, "edge_count": 0, "by_type": {}, "truncated": False, "last_updated_step": 0},
            attack_chain=None, confidence=0.0, sufficiency={"score": 0.0}, investigation_step=0,
            budget={"max_steps": b.max_investigation_steps, "max_events_per_query": b.max_events_per_query, "max_time_window_seconds": b.max_time_window_seconds,
                    "max_graph_nodes": b.max_graph_nodes, "max_llm_calls": b.max_llm_calls_per_investigation, "max_ti_lookups": b.max_ti_lookups_per_investigation,
                    "steps_used": 0, "llm_calls_used": 0, "ti_lookups_used": 0, "db_queries": 0, "events_retrieved": 0, "started_at": to_iso(utcnow()),
                    "timeout_seconds": b.investigation_timeout_seconds},
            termination_reason=None, final_report=None, agent_log=[], errors=[], seen_record_ids=[], status="running", executed_action_ids=[],
        )

    def _run(self, inv_id: str, stop_flag: threading.Event) -> None:
        coll = self.store["investigations"]
        doc = coll.find_one({"_id": inv_id})
        alert = self.store["alerts"].find_one({"_id": doc["alert_id"]})
        tools = ToolRegistry(self.repo, self.ti, self.graph, self.mitre, self.settings)
        steps: List[dict] = []

        def emit(action: dict) -> None:
            steps.append(action)
            self.bus.publish(inv_id, {"type": "agent_action", "investigation_id": inv_id, "action": action})

        ctx = AgentContext(tools=tools, graph=self.graph, mitre=self.mitre, llm=self.llm, settings=self.settings,
                           policy_mode=doc["policy"], mode=doc["mode"], profiles_by_type=self._profiles_by_type(), emit=emit)
        app = build_investigation_graph(ctx)
        state = self._initial_state(doc, alert)
        final_state: Optional[dict] = None
        try:
            for update in app.stream(state, stream_mode="values", config={"recursion_limit": 6 * self.settings.max_investigation_steps + 30}):
                final_state = update
                snapshot = _serialisable({k: v for k, v in update.items() if k not in ("last_tool_result", "seen_record_ids")})
                coll.update_one({"_id": inv_id}, {"$set": {"state": snapshot, "steps": steps, "status": update.get("status", "running"),
                                                          "metrics": self._metrics(update, tools)}})
                self.bus.publish(inv_id, {"type": "state", "investigation_id": inv_id, "summary": self._summary(update)})
                if stop_flag.is_set():
                    coll.update_one({"_id": inv_id}, {"$set": {"status": "stopped", "finished_at": utcnow()}})
                    self.bus.publish(inv_id, {"type": "done", "investigation_id": inv_id, "status": "stopped"})
                    return
            report = (final_state or {}).get("final_report")
            if report:
                self.store["reports"].replace_one({"investigation_id": inv_id}, {"_id": f"rpt_{inv_id}", **_serialisable(report)}, upsert=True)
            coll.update_one({"_id": inv_id}, {"$set": {"status": "completed", "finished_at": utcnow(), "metrics": self._metrics(final_state or {}, tools)}})
            self.store["alerts"].update_one({"_id": doc["alert_id"]}, {"$set": {"status": "resolved"}})
            self.bus.publish(inv_id, {"type": "done", "investigation_id": inv_id, "status": "completed"})
        except Exception as exc:
            log.exception("investigation %s failed", inv_id)
            coll.update_one({"_id": inv_id}, {"$set": {"status": "failed", "finished_at": utcnow(), "error": f"{type(exc).__name__}: {exc}",
                                                      "traceback": traceback.format_exc()[-4000:], "steps": steps}})
            self.bus.publish(inv_id, {"type": "done", "investigation_id": inv_id, "status": "failed", "error": str(exc)})

    @staticmethod
    def _metrics(state: dict, tools: ToolRegistry) -> dict:
        b = state.get("budget", {})
        gs = state.get("graph_state", {})
        started = b.get("started_at")
        latency = None
        if started:
            from backend.utils.timeutil import parse_dt
            latency = round((utcnow() - parse_dt(started)).total_seconds() * 1000)
        return {"steps": b.get("steps_used", 0), "db_queries": b.get("db_queries", 0), "events_retrieved": b.get("events_retrieved", 0),
                "llm_calls": b.get("llm_calls_used", 0), "ti_lookups": b.get("ti_lookups_used", 0), "evidence_items": len(state.get("evidence", [])),
                "graph_nodes": gs.get("node_count", 0), "graph_edges": gs.get("edge_count", 0), "tool_calls": len(tools.calls),
                "latency_ms": latency, "termination_reason": state.get("termination_reason"),
                "stage_count": (state.get("attack_chain") or {}).get("stage_count"), "confidence": state.get("confidence")}

    @staticmethod
    def _summary(state: dict) -> dict:
        return {"step": state.get("investigation_step"), "status": state.get("status"), "confidence": state.get("confidence"),
                "hypothesis": (state.get("current_hypothesis") or {}).get("statement"), "sufficiency": state.get("sufficiency"),
                "open_gaps": sum(1 for g in state.get("missing_evidence", []) if g.get("status") == "open"),
                "evidence_items": len(state.get("evidence", [])), "graph": state.get("graph_state"), "termination_reason": state.get("termination_reason")}
