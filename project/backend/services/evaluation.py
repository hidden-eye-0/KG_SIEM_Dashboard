"""Evaluation harness (brief §24): adaptive vs fixed-query baseline + grounding metrics.

Ground truth (`scenarios` collection + `security_events.ground_truth`) is NEVER visible to the
agents (the repository projects it out); this module is the only consumer.

Per investigation we compute:
  * cost: wall time, db queries, events retrieved, LLM calls, TI lookups, steps
  * evidence relevance: share of retrieved event records whose hidden ground_truth.scenario_id
    equals the alert's scenario (precision), and share of the scenario's attack flows that were
    retrieved (recall)
  * chain completeness: stage recall / precision vs the scenario's stage list, order agreement
    (Kendall-style pairwise), and whether the alerted stage is present
  * report quality proxies: claims with evidence ids, grounding checks passed, unknown ids/IPs
    in the narrative, forbidden phrases, "Insufficient evidence" statements present
"""
from __future__ import annotations

import logging
import statistics
import time
from typing import Any, Dict, List, Optional

from backend.services.mongo import DocumentStore
from backend.utils.ids import new_id
from backend.utils.timeutil import utcnow
from ml.preprocessing.labels import classify_label

log = logging.getLogger(__name__)


def _attack_type(raw_label: str) -> str:
    info, _ = classify_label(raw_label)
    return info.attack_type if info else raw_label


def _pairwise_order_agreement(truth: List[str], pred: List[str]) -> Optional[float]:
    """Fraction of ordered stage pairs from the truth (both present in pred) whose order pred preserves."""
    pos = {}
    for i, t in enumerate(pred):
        pos.setdefault(t, i)
    pairs = agree = 0
    for i in range(len(truth)):
        for j in range(i + 1, len(truth)):
            a, b = truth[i], truth[j]
            if a in pos and b in pos and a != b:
                pairs += 1
                agree += 1 if pos[a] < pos[b] else 0
    return round(agree / pairs, 3) if pairs else None


class Evaluator:
    def __init__(self, store: DocumentStore, runner):
        self.store, self.runner = store, runner

    # ------------------------------------------------------------------ ground truth helpers
    def scenario_for_alert(self, alert: dict) -> Optional[dict]:
        ev = self.store["security_events"].find_one({"_id": {"$in": alert.get("event_ids_sample", [])[:5]}}, {"ground_truth": 1})
        gt = (ev or {}).get("ground_truth") or {}
        if not gt.get("scenario_id"):
            return None
        return self.store["scenarios"].find_one({"_id": gt["scenario_id"]})

    def score_investigation(self, inv_id: str) -> dict:
        doc = self.store["investigations"].find_one({"_id": inv_id})
        if not doc or not doc.get("state"):
            raise KeyError(inv_id)
        st = doc["state"]
        alert = self.store["alerts"].find_one({"_id": doc["alert_id"]})
        scenario = self.scenario_for_alert(alert)
        chain = st.get("attack_chain") or {"stages": []}
        report = st.get("final_report") or {}
        metrics = doc.get("metrics", {})

        # ---- evidence relevance vs hidden ground truth
        record_ids = sorted({r for e in st.get("evidence", []) for r in e.get("record_ids", []) if str(r).startswith("evt_")})
        relevant = total = 0
        truth_attack_ids: set = set()
        if scenario:
            truth_attack_ids = {d["_id"] for d in self.store["security_events"].find({"ground_truth.scenario_id": scenario["_id"], "prediction.attack_type": {"$ne": "Benign"}}, {"_id": 1})}
            for chunk_start in range(0, len(record_ids), 2000):
                chunk = record_ids[chunk_start:chunk_start + 2000]
                for d in self.store["security_events"].find({"_id": {"$in": chunk}}, {"ground_truth.scenario_id": 1}):
                    total += 1
                    if (d.get("ground_truth") or {}).get("scenario_id") == scenario["_id"]:
                        relevant += 1
        evidence_precision = round(relevant / total, 3) if total else None
        evidence_recall = round(len(set(record_ids) & truth_attack_ids) / len(truth_attack_ids), 3) if truth_attack_ids else None

        # ---- chain completeness (attack types, order)
        truth_stages = [_attack_type(s["label"]) for s in (scenario or {}).get("stages", [])]
        pred_stages = [s["attack_type"] for s in chain.get("stages", []) if s.get("support") != "weak"]
        pred_all = [s["attack_type"] for s in chain.get("stages", [])]
        ts, ps = set(truth_stages), set(pred_stages)
        stage_recall = round(len(ts & ps) / len(ts), 3) if ts else None
        stage_precision = round(len(ts & ps) / len(ps), 3) if ps else None
        extra_stages = sorted(ps - ts)
        missed_stages = sorted(ts - ps)
        order_agreement = _pairwise_order_agreement(truth_stages, pred_stages)

        # ---- report grounding
        claims = report.get("claims", [])
        narr = (report.get("sections", {}).get("13_ai_attack_narrative") or {})
        grounding = narr.get("grounding_validation") or {}
        text = (narr.get("text") or "").lower()
        return {
            "investigation_id": inv_id, "alert_id": doc["alert_id"], "mode": doc["mode"], "policy": doc["policy"], "status": doc["status"],
            "alert_attack_type": alert["attack_type"], "scenario": scenario["name"] if scenario else None, "scenario_id": scenario["_id"] if scenario else None,
            "cost": {"latency_ms": metrics.get("latency_ms"), "steps": metrics.get("steps"), "db_queries": metrics.get("db_queries"), "events_retrieved": metrics.get("events_retrieved"),
                     "llm_calls": metrics.get("llm_calls"), "ti_lookups": metrics.get("ti_lookups"), "graph_nodes": metrics.get("graph_nodes"), "graph_edges": metrics.get("graph_edges"),
                     "termination_reason": st.get("termination_reason")},
            "evidence": {"records_retrieved_unique": len(record_ids), "relevant_records": relevant, "precision": evidence_precision, "recall": evidence_recall,
                         "truth_attack_flows": len(truth_attack_ids)},
            "chain": {"truth_stages": truth_stages, "predicted_stages": pred_stages, "predicted_all_including_weak": pred_all, "stage_recall": stage_recall,
                      "stage_precision": stage_precision, "order_agreement": order_agreement, "missed_stages": missed_stages, "extra_stages": extra_stages,
                      "complete": bool(ts) and ts <= ps, "alert_stage_present": alert["attack_type"] in ps},
            "report": {"claims": len(claims), "claims_with_evidence": sum(1 for c in claims if c.get("evidence_ids")),
                       "claims_validated": sum(1 for c in claims if c.get("validated")),
                       "narrative_source": "gemini" if (report.get("llm") or {}).get("used") else "template", "grounding_passed": grounding.get("passed"), "unknown_evidence_ids": len(grounding.get("unknown_evidence_ids", [])),
                       "unknown_ips": len(grounding.get("unknown_ips", [])), "forbidden_phrases": len(grounding.get("forbidden_phrases", [])),
                       "states_insufficient_evidence": ("insufficient evidence" in text) or ("not available from the current evidence" in text),
                       "confidence": st.get("confidence"), "sufficiency": (st.get("sufficiency") or {}).get("score")},
        }

    # ------------------------------------------------------------------ paired runs
    def run_comparison(self, alert_ids: Optional[List[str]] = None, n_alerts: int = 6, policies: Optional[List[str]] = None, name: str = "") -> dict:
        """Run adaptive and baseline investigations for the same alerts and aggregate."""
        if not alert_ids:
            # a spread across categories, preferring multi-stage scenarios
            alerts = list(self.store["alerts"].find({}, {"_id": 1, "category": 1, "attack_type": 1, "severity": 1}).limit(500))
            by_cat: Dict[str, list] = {}
            for a in alerts:
                by_cat.setdefault(a["category"], []).append(a)
            alert_ids = []
            while len(alert_ids) < min(n_alerts, len(alerts)):
                progressed = False
                for cat in sorted(by_cat):
                    if by_cat[cat] and len(alert_ids) < n_alerts:
                        alert_ids.append(by_cat[cat].pop(0)["_id"])
                        progressed = True
                if not progressed:
                    break
        run_id = new_id("evl")
        rows = []
        t0 = time.time()
        arms = [("adaptive", p) for p in (policies or [None])] + [("baseline", None)]
        for aid in alert_ids:
            for mode, pol in arms:
                inv = self.runner.create(aid, mode=mode, policy=pol)
                self.runner.run_sync(inv["_id"])
                try:
                    rows.append(self.score_investigation(inv["_id"]))
                except Exception as exc:  # keep going; record failure
                    log.exception("scoring failed")
                    rows.append({"investigation_id": inv["_id"], "alert_id": aid, "mode": mode, "status": "score_failed", "error": str(exc)})
        summary = self.aggregate(rows)
        doc = {"_id": run_id, "name": name or f"comparison {utcnow().isoformat()}", "created_at": utcnow(), "alert_ids": alert_ids, "arms": [f"{m}:{p or 'default'}" for m, p in arms],
               "rows": rows, "summary": summary, "wall_seconds": round(time.time() - t0, 2),
               "notes": ["Ground truth comes from the Scenario Contextualiser (synthesized entity context attached to labelled flows); it is hidden from agents and used only here.",
                         "Baseline arm = same graph/report code with a fixed 3-query plan (events by source IP, alerts by source, MITRE map).",
                         "Evidence precision/recall are computed over event records actually returned to the agents, versus the hidden scenario membership.",
                         "Data source: " + ("synthetic_demo (placeholder data — not dataset statistics)" if self._demo() else "contextualised CICIoT2023 flows")]}
        self.store["evaluation_runs"].insert_one(doc)
        return doc

    def _demo(self) -> bool:
        ev = self.store["security_events"].find_one({}, {"dataset.source": 1})
        return bool(ev and (ev.get("dataset") or {}).get("source") == "synthetic_demo")

    @staticmethod
    def aggregate(rows: List[dict]) -> dict:
        def mean(vals):
            vals = [v for v in vals if isinstance(v, (int, float))]
            return round(statistics.mean(vals), 3) if vals else None

        out = {}
        for mode in sorted({r.get("mode") for r in rows if r.get("mode")}):
            rs = [r for r in rows if r.get("mode") == mode and r.get("status") == "completed"]
            if not rs:
                out[mode] = {"n": 0}
                continue
            out[mode] = {
                "n": len(rs),
                "latency_ms": mean(r["cost"]["latency_ms"] for r in rs), "steps": mean(r["cost"]["steps"] for r in rs),
                "db_queries": mean(r["cost"]["db_queries"] for r in rs), "events_retrieved": mean(r["cost"]["events_retrieved"] for r in rs),
                "llm_calls": mean(r["cost"]["llm_calls"] for r in rs), "ti_lookups": mean(r["cost"]["ti_lookups"] for r in rs),
                "graph_nodes": mean(r["cost"]["graph_nodes"] for r in rs),
                "evidence_precision": mean(r["evidence"]["precision"] for r in rs), "evidence_recall": mean(r["evidence"]["recall"] for r in rs),
                "stage_recall": mean(r["chain"]["stage_recall"] for r in rs), "stage_precision": mean(r["chain"]["stage_precision"] for r in rs),
                "order_agreement": mean(r["chain"]["order_agreement"] for r in rs),
                "chain_complete_rate": mean(1.0 if r["chain"]["complete"] else 0.0 for r in rs),
                "claims": mean(r["report"]["claims"] for r in rs),
                "claim_evidence_rate": mean((r["report"]["claims_with_evidence"] / r["report"]["claims"]) if r["report"]["claims"] else None for r in rs),
                "grounding_pass_rate": mean(1.0 if r["report"]["grounding_passed"] else 0.0 for r in rs if r["report"]["grounding_passed"] is not None),
                "hallucinated_ids_per_report": mean(r["report"]["unknown_evidence_ids"] + r["report"]["unknown_ips"] for r in rs),
                "llm_narratives": sum(1 for r in rs if r["report"]["narrative_source"] == "gemini"),
                "termination_reasons": {t: sum(1 for r in rs if r["cost"]["termination_reason"] == t) for t in sorted({r["cost"]["termination_reason"] for r in rs})},
            }
        return out
