"""LangGraph shared investigation state (architecture review §7).

The state is a TypedDict of plain JSON-serialisable structures so it can be
checkpointed to MongoDB, streamed to the UI and reproduced offline.  Lists marked with
`operator.add` are append-only across nodes.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


class Hypothesis(TypedDict, total=False):
    id: str
    statement: str
    attack_type: str
    category: str
    confidence: float
    stages: List[str]                  # ordered attack types believed to be linked
    supporting_evidence_ids: List[str]
    contradicting_evidence_ids: List[str]
    alternatives: List[str]
    updated_at_step: int


class Entity(TypedDict, total=False):
    key: str                           # e.g. "IP:203.0.113.24"
    type: str                          # IP | Device | Domain | IOC | MITRETechnique | Attack
    value: str
    role: str                          # source | target | related | indicator
    first_seen: Optional[str]
    last_seen: Optional[str]
    evidence_ids: List[str]
    properties: Dict[str, Any]


class EvidenceItem(TypedDict, total=False):
    evidence_id: str
    step: int
    tool: str
    args: Dict[str, Any]
    summary: str
    record_ids: List[str]              # security_event ids (sample, <= MAX_EVENTS_PER_QUERY)
    record_count: int
    total_matched: int
    truncated: bool
    time_range: Dict[str, Optional[str]]
    attack_types: Dict[str, int]       # predicted attack types present in the records
    entities_found: List[str]
    relevance: str                     # supporting | contradicting | contextual | empty
    provenance: Dict[str, Any]
    latency_ms: float
    novelty: int                       # number of record ids not seen before


class EvidenceGap(TypedDict, total=False):
    gap_id: str
    requirement_id: str
    description: str
    priority: str                      # critical | high | medium | low
    status: str                        # open | resolved | unresolvable
    resolved_by: Optional[str]
    opened_at_step: int


class CandidateAction(TypedDict, total=False):
    action_id: str
    tool: str
    args: Dict[str, Any]
    rationale: str
    closes_gap_ids: List[str]
    expected_gain: float
    cost: float
    utility: float


class ActionRecord(TypedDict, total=False):
    action_id: str
    tool: str
    args: Dict[str, Any]
    chosen_by: str                     # llm | heuristic | fixed
    reasoning: str
    step: int
    alternatives_considered: int


class ToolCall(TypedDict, total=False):
    step: int
    tool: str
    args: Dict[str, Any]
    status: str
    count: int
    total_matched: int
    latency_ms: float
    query_digest: str
    evidence_id: Optional[str]


class GraphSummary(TypedDict, total=False):
    node_count: int
    edge_count: int
    by_type: Dict[str, int]
    truncated: bool
    last_updated_step: int


class SufficiencyScore(TypedDict, total=False):
    score: float
    coverage: float
    hypothesis_confidence: float
    chain_connectivity: float
    open_critical: int
    novelty_last_k: List[int]
    reason: str


class Budget(TypedDict, total=False):
    max_steps: int
    max_events_per_query: int
    max_time_window_seconds: int
    max_graph_nodes: int
    max_llm_calls: int
    max_ti_lookups: int
    steps_used: int
    llm_calls_used: int
    ti_lookups_used: int
    db_queries: int
    events_retrieved: int
    started_at: str
    timeout_seconds: int


class AgentAction(TypedDict, total=False):
    step: int
    agent: str
    node: str
    title: str
    detail: str
    tool: Optional[str]
    args: Dict[str, Any]
    evidence_ids: List[str]
    llm_used: bool
    latency_ms: float
    timestamp: str
    status: str


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    alert_id: str
    mode: str                          # adaptive | baseline
    policy: str                        # llm | heuristic | fixed
    alert: Dict[str, Any]
    current_hypothesis: Hypothesis
    entities: Dict[str, Entity]
    evidence: Annotated[List[EvidenceItem], operator.add]
    missing_evidence: List[EvidenceGap]
    candidate_actions: List[CandidateAction]
    last_action: Optional[ActionRecord]
    last_tool_result: Optional[Dict[str, Any]]
    tool_history: Annotated[List[ToolCall], operator.add]
    threat_intelligence: Dict[str, Any]
    mitre_mappings: List[Dict[str, Any]]
    graph_state: GraphSummary
    attack_chain: Optional[Dict[str, Any]]
    confidence: float
    sufficiency: SufficiencyScore
    investigation_step: int
    budget: Budget
    termination_reason: Optional[str]
    final_report: Optional[Dict[str, Any]]
    agent_log: Annotated[List[AgentAction], operator.add]
    errors: Annotated[List[str], operator.add]
    seen_record_ids: List[str]
    executed_action_ids: List[Dict[str, Any]]
    status: str
