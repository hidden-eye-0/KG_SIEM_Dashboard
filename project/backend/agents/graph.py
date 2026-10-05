"""LangGraph wiring of the investigation loop (architecture review §7).

    START → interpret_alert → build_initial_graph → assess_gaps → decide_action
    decide_action ──(action)──► execute_tool → update_graph → reassess → assess_gaps  (loop)
                  ──(stop)────► reconstruct → narrate_and_report → END

The baseline (non-adaptive) arm uses the SAME graph with `mode="baseline"`: assess_gaps
then returns the fixed plan and decide_action executes it in order — which keeps the
comparison fair (same tools, same graph builder, same report).
"""
from __future__ import annotations

import logging
from functools import partial
from typing import Callable, Dict, Optional

from langgraph.graph import END, START, StateGraph

from backend.agents import agents as A
from backend.agents.agents import AgentContext
from backend.agents.state import InvestigationState

log = logging.getLogger(__name__)

# Declared node contracts (read/written keys) — enforced by tests/unit/test_contracts.py
NODE_CONTRACTS: Dict[str, Dict[str, list]] = {
    "interpret_alert": {"reads": ["alert", "budget"], "writes": ["entities", "current_hypothesis", "confidence", "agent_log", "status"], "llm": True},
    "build_initial_graph": {"reads": ["alert", "investigation_id", "mode"], "writes": ["graph_state", "agent_log"], "llm": False},
    "assess_gaps": {"reads": ["alert", "current_hypothesis", "evidence", "tool_history", "entities", "threat_intelligence", "mitre_mappings", "missing_evidence", "mode"],
                    "writes": ["missing_evidence", "candidate_actions", "agent_log"], "llm": False},
    "decide_action": {"reads": ["candidate_actions", "missing_evidence", "budget", "current_hypothesis", "graph_state", "evidence", "mode"],
                      "writes": ["last_action", "termination_reason", "sufficiency", "current_hypothesis", "agent_log", "executed_action_ids"], "llm": True},
    "execute_tool": {"reads": ["last_action", "alert", "investigation_id", "budget", "seen_record_ids", "threat_intelligence", "mitre_mappings"],
                     "writes": ["evidence", "tool_history", "last_tool_result", "budget", "investigation_step", "seen_record_ids", "threat_intelligence", "mitre_mappings", "agent_log"], "llm": False},
    "update_graph": {"reads": ["last_tool_result", "alert", "investigation_id", "entities", "budget", "graph_state"], "writes": ["graph_state", "entities", "agent_log"], "llm": False},
    "reassess": {"reads": ["current_hypothesis", "alert", "evidence", "investigation_id", "budget", "last_tool_result"], "writes": ["current_hypothesis", "confidence", "agent_log"], "llm": True},
    "reconstruct": {"reads": ["investigation_id", "alert", "evidence", "graph_state"], "writes": ["attack_chain", "agent_log"], "llm": False},
    "narrate_and_report": {"reads": ["alert", "attack_chain", "current_hypothesis", "evidence", "threat_intelligence", "mitre_mappings", "entities", "graph_state", "budget", "termination_reason"],
                           "writes": ["final_report", "agent_log", "status"], "llm": True},
}


def _route_after_decision(state: InvestigationState) -> str:
    return "execute_tool" if state.get("last_action") else "reconstruct"


def build_investigation_graph(ctx: AgentContext, checkpointer=None):
    g = StateGraph(InvestigationState)
    g.add_node("interpret_alert", partial(A.interpret_alert, ctx=ctx))
    g.add_node("build_initial_graph", partial(A.build_initial_graph, ctx=ctx))
    g.add_node("assess_gaps", partial(A.assess_gaps, ctx=ctx))
    g.add_node("decide_action", partial(A.decide_action, ctx=ctx))
    g.add_node("execute_tool", partial(A.execute_tool, ctx=ctx))
    g.add_node("update_graph", partial(A.update_graph, ctx=ctx))
    g.add_node("reassess", partial(A.reassess, ctx=ctx))
    g.add_node("reconstruct", partial(A.reconstruct, ctx=ctx))
    g.add_node("narrate_and_report", partial(A.narrate_and_report, ctx=ctx))

    g.add_edge(START, "interpret_alert")
    g.add_edge("interpret_alert", "build_initial_graph")
    g.add_edge("build_initial_graph", "assess_gaps")
    g.add_edge("assess_gaps", "decide_action")
    g.add_conditional_edges("decide_action", _route_after_decision, {"execute_tool": "execute_tool", "reconstruct": "reconstruct"})
    g.add_edge("execute_tool", "update_graph")
    g.add_edge("update_graph", "reassess")
    g.add_edge("reassess", "assess_gaps")
    g.add_edge("reconstruct", "narrate_and_report")
    g.add_edge("narrate_and_report", END)
    return g.compile(checkpointer=checkpointer)
