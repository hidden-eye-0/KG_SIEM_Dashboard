"""Action-selection policy for the adaptive evidence-collection agent.

Given the current state and the code-generated candidate actions, the policy returns
either one candidate (possibly with bounded argument adjustments) or STOP.

    llm       : Gemini chooses among the candidates with structured output; falls back to
                the heuristic if the response is missing/invalid
    heuristic : argmax(utility) with novelty discounting (deterministic, reproducible)
    fixed     : baseline arm — executes a predefined list (no adaptation)

The LLM never invents tools or arguments outside the candidate set; it may only lower a
`limit` or shrink a time window (bounded adjustments), never raise them.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from backend.agents.state import CandidateAction, InvestigationState
from backend.services.gemini import GeminiClient

log = logging.getLogger(__name__)

DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "action_id": {"type": "string", "description": "one of the candidate action ids, or STOP"},
        "reasoning": {"type": "string"},
        "hypothesis_update": {"type": "string", "description": "one-sentence updated hypothesis or empty"},
        "confidence": {"type": "number"},
    },
    "required": ["action_id", "reasoning"],
}

SYSTEM_PROMPT = """You are the Adaptive Evidence Collection Agent of a SOC investigation system.
You decide which evidence to retrieve NEXT, given the current investigation state and a list of
candidate actions generated from the open evidence gaps. Rules:
- Choose exactly one candidate action_id, or STOP if the open gaps no longer matter for the hypothesis.
- Prefer actions that resolve critical/high gaps, that are novel (not repeating earlier queries) and cheap.
- Network-flow features are behavioral evidence, not proof of the underlying actions. Never assume facts
  that are not in the state. Never invent evidence.
- Respond with JSON only."""


def compress_state_for_llm(state: InvestigationState, candidates: List[CandidateAction]) -> str:
    """retrieve -> filter -> compress -> structure: a compact, bounded view of the state."""
    hyp = state.get("current_hypothesis") or {}
    ev_lines = []
    for e in state.get("evidence", [])[-8:]:
        ev_lines.append({"id": e["evidence_id"], "tool": e["tool"], "count": e.get("record_count"), "total": e.get("total_matched"),
                         "attack_types": e.get("attack_types"), "summary": (e.get("summary") or "")[:160]})
    gaps = [{"id": g["requirement_id"], "priority": g["priority"], "desc": g["description"][:100]}
            for g in state.get("missing_evidence", []) if g["status"] == "open"][:10]
    cands = [{"action_id": c["action_id"], "tool": c["tool"], "closes": c["closes_gap_ids"], "utility": c["utility"],
              "rationale": c["rationale"][:140]} for c in candidates[:10]]
    payload = {
        "alert": {k: state["alert"].get(k) for k in ("attack_type", "category", "severity", "source_ip", "destination_ips", "event_count", "first_seen", "last_seen")},
        "hypothesis": {k: hyp.get(k) for k in ("statement", "attack_type", "category", "confidence", "stages")},
        "step": state.get("investigation_step"),
        "budget_left": {"steps": state["budget"]["max_steps"] - state["budget"]["steps_used"],
                        "llm_calls": state["budget"]["max_llm_calls"] - state["budget"]["llm_calls_used"]},
        "sufficiency": state.get("sufficiency"),
        "recent_evidence": ev_lines,
        "open_gaps": gaps,
        "threat_intel_status": {k: v.get("status") if isinstance(v, dict) else str(v) for k, v in list(state.get("threat_intelligence", {}).items())[:5]},
        "graph": state.get("graph_state"),
        "candidates": cands,
    }
    return json.dumps(payload, default=str)


class Policy:
    def __init__(self, mode: str, llm: Optional[GeminiClient]):
        self.mode = mode
        self.llm = llm

    def choose(self, state: InvestigationState, candidates: List[CandidateAction]) -> Tuple[Optional[CandidateAction], Dict[str, Any]]:
        if not candidates:
            return None, {"chosen_by": self.mode, "reasoning": "no candidate actions", "alternatives_considered": 0}
        if self.mode == "llm" and self.llm is not None and self.llm.available \
                and state["budget"]["llm_calls_used"] < state["budget"]["max_llm_calls"]:
            choice, meta = self._llm_choose(state, candidates)
            if choice is not None or meta.get("stop"):
                return choice, meta
            log.info("LLM decision invalid/unavailable -> heuristic fallback")
        return self._heuristic(candidates)

    # ------------------------------------------------------------------ heuristic
    @staticmethod
    def _heuristic(candidates: List[CandidateAction]) -> Tuple[CandidateAction, Dict[str, Any]]:
        best = max(candidates, key=lambda c: (c["utility"], c["expected_gain"]))
        return best, {"chosen_by": "heuristic", "reasoning": f"highest utility ({best['utility']}) among {len(candidates)} candidates: {best['rationale']}",
                      "alternatives_considered": len(candidates)}

    # ------------------------------------------------------------------ llm
    def _llm_choose(self, state: InvestigationState, candidates: List[CandidateAction]) -> Tuple[Optional[CandidateAction], Dict[str, Any]]:
        prompt = compress_state_for_llm(state, candidates)
        resp = self.llm.generate_json(SYSTEM_PROMPT, prompt, schema=DECISION_SCHEMA, temperature=0.1, max_output_tokens=600)
        state["budget"]["llm_calls_used"] += 1
        if not resp or "action_id" not in resp:
            return None, {"chosen_by": "llm", "reasoning": "invalid LLM response", "alternatives_considered": len(candidates), "llm_failed": True}
        aid = str(resp["action_id"]).strip()
        meta = {"chosen_by": "llm", "reasoning": str(resp.get("reasoning", ""))[:600], "alternatives_considered": len(candidates),
                "hypothesis_update": (resp.get("hypothesis_update") or "").strip()[:400], "llm_confidence": resp.get("confidence")}
        if aid.upper() == "STOP":
            meta["stop"] = True
            return None, meta
        for c in candidates:
            if c["action_id"] == aid:
                return c, meta
        meta["reasoning"] += f" (action_id '{aid}' not in candidates)"
        return None, meta
