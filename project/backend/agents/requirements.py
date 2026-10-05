"""Evidence requirements and candidate-action generation (architecture review §10).

A *requirement* says what must be known for the current hypothesis to be considered
investigated.  Which requirements apply depends on the CURRENT hypothesis category/type
and the entities discovered so far — so as evidence changes the hypothesis, the set of
open gaps and the generated candidate actions change with it.  That state-dependence
is what makes the loop adaptive rather than a fixed query sequence.

Each requirement provides:
    applies(state)          -> bool
    satisfied(state)        -> bool
    candidates(state)       -> list[CandidateAction]   (tool + args + rationale)
"""
from __future__ import annotations

from datetime import timedelta
from typing import Callable, Dict, List

from backend.agents.state import CandidateAction, InvestigationState
from backend.utils.ipaddr import is_lookup_worthy
from backend.utils.timeutil import parse_dt, to_iso

PRIORITY_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}


def _hyp(state: InvestigationState) -> dict:
    return state.get("current_hypothesis") or {}


def _cat(state: InvestigationState) -> str:
    return _hyp(state).get("category") or state["alert"].get("category")


def _atype(state: InvestigationState) -> str:
    return _hyp(state).get("attack_type") or state["alert"].get("attack_type")


def _src(state: InvestigationState) -> str:
    return state["alert"]["source_ip"]


def _targets(state: InvestigationState) -> List[str]:
    return list(state["alert"].get("destination_ips") or [])


def _devices(state: InvestigationState) -> List[str]:
    return list(state["alert"].get("device_ids") or [])


def _tools_done(state: InvestigationState, tool: str, **arg_filters) -> List[dict]:
    out = []
    for c in state.get("tool_history", []):
        if c["tool"] != tool:
            continue
        args = c.get("args", {})
        if all(args.get(k) == v for k, v in arg_filters.items()):
            out.append(c)
    return out


def _ev_with(state: InvestigationState, tool: str, **arg_filters) -> List[dict]:
    out = []
    for e in state.get("evidence", []):
        if e["tool"] != tool:
            continue
        if all(e.get("args", {}).get(k) == v for k, v in arg_filters.items()):
            out.append(e)
    return out


def _alert_window(state: InvestigationState):
    return parse_dt(state["alert"]["first_seen"]), parse_dt(state["alert"]["last_seen"])


def _discovered_attack_types(state: InvestigationState) -> Dict[str, int]:
    agg: Dict[str, int] = {}
    for e in state.get("evidence", []):
        for k, v in (e.get("attack_types") or {}).items():
            agg[k] = agg.get(k, 0) + v
    return agg


class Requirement:
    def __init__(self, rid: str, description: str, priority: str,
                 applies: Callable[[InvestigationState], bool],
                 satisfied: Callable[[InvestigationState], bool],
                 candidates: Callable[[InvestigationState], List[CandidateAction]]):
        self.id, self.description, self.priority = rid, description, priority
        self.applies, self.satisfied, self.candidates = applies, satisfied, candidates


def _cand(action_id: str, tool: str, args: dict, rationale: str, req: str, gain: float, cost: float = 1.0) -> CandidateAction:
    return CandidateAction(action_id=action_id, tool=tool, args=args, rationale=rationale, closes_gap_ids=[req],
                           expected_gain=gain, cost=cost, utility=round(gain / max(cost, 0.1), 3))


# --------------------------------------------------------------------------- requirement table
def build_requirements(max_window: int) -> List[Requirement]:
    reqs: List[Requirement] = []

    # R1 source history --------------------------------------------------------------
    def r1_sat(s):
        return bool(_ev_with(s, "get_events_by_ip", ip=_src(s), role="src")) or bool(_ev_with(s, "get_event_aggregates", group_by="attack_type"))

    def r1_cands(s):
        first, last = _alert_window(s)
        w = min(max_window, 6 * 3600)
        return [
            _cand("src_history_agg", "get_event_aggregates",
                  {"group_by": "attack_type", "filters": {"source_ip": _src(s)}, "start": to_iso(first - timedelta(seconds=w)), "end": to_iso(last + timedelta(seconds=w))},
                  f"Summarise all predicted activity from {_src(s)} around the alert window without pulling rows", "source_history", 3.0, 0.5),
            _cand("src_history_rows", "get_events_by_ip",
                  {"ip": _src(s), "role": "src", "start": to_iso(first - timedelta(seconds=w)), "end": to_iso(last + timedelta(seconds=w)),
                   "exclude_attack_type": s["alert"]["attack_type"], "limit": 200},
                  f"Retrieve non-{s['alert']['attack_type']} flows from {_src(s)} to find other behaviour of the same source", "source_history", 3.0, 1.0),
        ]
    reqs.append(Requirement("source_history", "Other activity of the source IP around the alert window", "critical", lambda s: True, r1_sat, r1_cands))

    # R2 target breadth ---------------------------------------------------------------
    def r2_sat(s):
        return bool(_ev_with(s, "get_event_aggregates", group_by="destination_ip"))

    def r2_cands(s):
        first, last = _alert_window(s)
        return [_cand("target_breadth", "get_event_aggregates",
                      {"group_by": "destination_ip", "filters": {"source_ip": _src(s)}, "start": to_iso(first - timedelta(hours=1)), "end": to_iso(last + timedelta(hours=1))},
                      f"How many distinct destinations did {_src(s)} contact? (scan/flood breadth)", "target_breadth", 2.0, 0.5)]
    reqs.append(Requirement("target_breadth", "Number of distinct targets contacted by the source", "high",
                            lambda s: _cat(s) in ("DDoS", "DoS", "Reconnaissance", "Spoofing"), r2_sat, r2_cands))

    # R3 follow-on activity (what happened AFTER the alert) -----------------------------
    def r3_sat(s):
        return bool(_ev_with(s, "get_related_events", strategy="follow_on"))

    def r3_cands(s):
        return [_cand("follow_on", "get_related_events", {"alert": s["alert"], "strategy": "follow_on", "window_seconds": min(max_window, 3 * 3600), "limit": 300},
                      f"Did {_src(s)} do anything else after the {s['alert']['attack_type']} activity ended? (progression to later stages)", "follow_on_activity", 3.0, 1.0)]
    reqs.append(Requirement("follow_on_activity", "Activity of the source after the alert (possible later stages)", "critical",
                            lambda s: _cat(s) in ("Reconnaissance", "Brute Force", "Spoofing", "Web-Based"), r3_sat, r3_cands))

    # R4 precursor activity (what happened BEFORE) ---------------------------------------
    def r4_sat(s):
        return bool(_ev_with(s, "get_related_events", strategy="precursor"))

    def r4_cands(s):
        return [_cand("precursor", "get_related_events", {"alert": s["alert"], "strategy": "precursor", "window_seconds": min(max_window, 3 * 3600), "limit": 300},
                      f"Was there reconnaissance or other activity from {_src(s)} before the {s['alert']['attack_type']}? (earlier stages)", "precursor_activity", 2.5, 1.0)]
    reqs.append(Requirement("precursor_activity", "Activity of the source before the alert (possible earlier stages)", "high",
                            lambda s: _cat(s) in ("Web-Based", "Brute Force", "DoS", "DDoS", "Spoofing"), r4_sat, r4_cands))

    # R5 authentication-protocol activity on the target --------------------------------------
    def r5_applies(s):
        disc = _discovered_attack_types(s)
        return _cat(s) in ("Brute Force", "Web-Based") or "Dictionary Brute Force" in disc or "Dictionary Brute Force" in _hyp(s).get("stages", [])

    def r5_sat(s):
        return bool(_ev_with(s, "get_authentication_events", ip=_src(s)))

    def r5_cands(s):
        first, last = _alert_window(s)
        return [_cand("auth_source", "get_authentication_events", {"ip": _src(s), "start": to_iso(first - timedelta(hours=2)), "end": to_iso(last + timedelta(hours=2)), "limit": 300},
                      f"SSH/Telnet-indicator flows from {_src(s)} to any device (network evidence of authentication-protocol activity)", "auth_protocol_activity", 2.0, 1.0)]
    reqs.append(Requirement("auth_protocol_activity", "Authentication-protocol flows touching the target/source", "high", r5_applies, r5_sat, r5_cands))

    # R6 DNS context for spoofing -------------------------------------------------------------
    def r6_sat(s):
        return bool(_ev_with(s, "get_dns_events"))

    def r6_cands(s):
        first, last = _alert_window(s)
        tgt = _targets(s)[0] if _targets(s) else None
        return [_cand("dns_ctx", "get_dns_events", {"ip": tgt or _src(s), "start": to_iso(first - timedelta(hours=1)), "end": to_iso(last + timedelta(hours=1)), "limit": 300},
                      "DNS-indicator flows on the affected segment (spoofing context)", "dns_context", 1.5, 1.0)]
    reqs.append(Requirement("dns_context", "DNS-indicator flows around the affected devices", "medium",
                            lambda s: _cat(s) == "Spoofing" or "DNS Spoofing" in _discovered_attack_types(s), r6_sat, r6_cands))

    # R7 related alerts ---------------------------------------------------------------
    def r7_sat(s):
        return bool(_ev_with(s, "search_alerts", source_ip=_src(s)))

    def r7_cands(s):
        return [_cand("related_alerts_src", "search_alerts", {"source_ip": _src(s), "exclude_alert_id": s["alert_id"], "limit": 50},
                      f"Other alerts raised for source {_src(s)} (correlation across detections)", "related_alerts", 2.0, 0.5)]
    reqs.append(Requirement("related_alerts", "Other alerts involving the same source", "high", lambda s: True, r7_sat, r7_cands))

    # R7b related alerts on the target (only once a target exists and the source view is done)
    def r7b_sat(s):
        return any(_ev_with(s, "search_alerts", destination_ip=t) for t in _targets(s)[:1])

    def r7b_cands(s):
        tgt = _targets(s)[0]
        return [_cand("related_alerts_dst", "search_alerts", {"destination_ip": tgt, "exclude_alert_id": s["alert_id"], "limit": 50},
                      f"Other alerts targeting {tgt} (is the device under attack from several sources?)", "target_alerts", 1.5, 0.5)]
    reqs.append(Requirement("target_alerts", "Other alerts targeting the same device", "medium",
                            lambda s: bool(_targets(s)) and r7_sat(s), r7b_sat, r7b_cands))

    # R8 same-target other sources (distributed attacks) -----------------------------------------
    def r8_sat(s):
        return bool(_ev_with(s, "get_related_events", strategy="same_target"))

    def r8_cands(s):
        return [_cand("same_target", "get_related_events", {"alert": s["alert"], "strategy": "same_target", "window_seconds": 300, "limit": 300},
                      "Flows from OTHER sources against the same target during the alert (distributed vs single-source)", "other_sources_same_target", 3.5, 1.0)]
    reqs.append(Requirement("other_sources_same_target", "Other sources hitting the same target (distributed attack check)", "critical",
                            lambda s: _cat(s) in ("DDoS", "DoS"), r8_sat, r8_cands))

    # R9 external reputation ---------------------------------------------------------------
    def r9_applies(s):
        return True

    def r9_sat(s):
        ti = s.get("threat_intelligence", {})
        return _src(s) in ti

    def r9_cands(s):
        src = _src(s)
        public = is_lookup_worthy(src)
        gain = 1.5 if public else 0.6
        return [_cand("ti_src_vt", "check_virustotal_ip", {"ip": src}, f"VirusTotal reputation for {src}" + ("" if public else " (documentation/private range: provider lookup will be skipped and recorded)"), "external_reputation", gain, 2.0 if public else 0.3),
                _cand("ti_src_otx", "check_otx_indicator", {"indicator": src, "type": "ip"}, f"OTX pulses for {src}", "external_reputation", gain, 1.5 if public else 0.3)]
    reqs.append(Requirement("external_reputation", "External reputation of the source indicator", "medium", r9_applies, r9_sat, r9_cands))

    # R10 technique mapping ---------------------------------------------------------------
    def r10_sat(s):
        mapped = {m["attack_type"] for m in s.get("mitre_mappings", [])}
        needed = {_atype(s), *(_hyp(s).get("stages") or [])}
        return needed <= mapped

    def r10_cands(s):
        mapped = {m["attack_type"] for m in s.get("mitre_mappings", [])}
        needed = [t for t in [_atype(s), *(_hyp(s).get("stages") or [])] if t not in mapped]
        if not needed:
            return []
        return [_cand("mitre_map", "map_attack_to_mitre", {"attack_types": needed[:8]},
                      "ATT&CK technique mapping for: " + ", ".join(needed[:8]), "technique_mapping", 1.0, 0.4)]
    reqs.append(Requirement("technique_mapping", "ATT&CK mapping for every attack type in the hypothesis", "medium", lambda s: True, r10_sat, r10_cands))

    # R11 target response profile (floods) --------------------------------------------------
    def r11_sat(s):
        return bool(_ev_with(s, "get_event_aggregates", group_by="protocol"))

    def r11_cands(s):
        first, last = _alert_window(s)
        tgt = _targets(s)[0]
        return [_cand("target_protocols", "get_event_aggregates", {"group_by": "protocol", "filters": {"destination_ip": tgt}, "start": to_iso(first - timedelta(minutes=30)), "end": to_iso(last + timedelta(minutes=30))},
                      f"Protocol mix of traffic reaching {tgt} during the flood (was normal service traffic present?)", "target_traffic_profile", 1.2, 0.5)]
    reqs.append(Requirement("target_traffic_profile", "Protocol mix at the target during the incident", "medium",
                            lambda s: _cat(s) in ("DDoS", "DoS") and bool(_targets(s)), r11_sat, r11_cands))

    # R12 device timeline once a target device is known and multiple stages are suspected -------------
    def r12_applies(s):
        return bool(_devices(s)) and (len(_hyp(s).get("stages") or []) >= 2 or len(_discovered_attack_types(s)) >= 2)

    def r12_sat(s):
        return any(_ev_with(s, "search_security_events", filters={"device_id": d, "source_ip": _src(s)}) for d in _devices(s)[:1])

    def r12_cands(s):
        first, last = _alert_window(s)
        d = _devices(s)[0]
        return [_cand("device_timeline_src", "search_security_events", {"filters": {"device_id": d, "source_ip": _src(s)}, "start": to_iso(first - timedelta(hours=2)), "end": to_iso(last + timedelta(hours=2)), "limit": 300},
                      f"Timeline of everything {_src(s)} sent to device {d} (±2h) to order the suspected stages", "device_timeline", 2.0, 1.0),
                _cand("device_timeline_all", "get_events_by_device", {"device_id": d, "start": to_iso(first - timedelta(minutes=30)), "end": to_iso(last + timedelta(minutes=30)), "limit": 300},
                      f"All traffic reaching device {d} around the alert (±30 min) — other sources active on the same device", "device_timeline", 1.2, 1.5)]
    reqs.append(Requirement("device_timeline", "Complete traffic timeline of the primary target device", "high", r12_applies, r12_sat, r12_cands))

    # R13 follow-on for discovered secondary source? (stage expansion) --------------------------------
    def r13_applies(s):
        disc = _discovered_attack_types(s)
        later = [t for t in disc if t != s["alert"]["attack_type"]]
        return bool(later) and _cat(s) not in ("DDoS", "DoS")

    def r13_sat(s):
        # satisfied once we've searched alerts for the source after discovering stages AND the source-scoped device timeline exists
        return bool(_ev_with(s, "search_alerts", source_ip=_src(s))) and (not _devices(s) or any(_ev_with(s, "search_security_events", filters={"device_id": d, "source_ip": _src(s)}) for d in _devices(s)[:1]))

    reqs.append(Requirement("stage_confirmation", "Confirm discovered secondary stages via alerts and device timeline", "high", r13_applies, r13_sat, lambda s: []))

    return reqs


# --------------------------------------------------------------------------- baseline fixed plan
def fixed_baseline_plan(state: InvestigationState) -> List[CandidateAction]:
    """The non-adaptive comparison arm: the same three queries for every alert."""
    first, last = _alert_window(state)
    return [
        _cand("fixed_1", "get_events_by_ip", {"ip": _src(state), "role": "src", "start": to_iso(first - timedelta(hours=1)), "end": to_iso(last + timedelta(hours=1)), "limit": 200},
              "Fixed baseline query 1: source activity ±1h", "baseline", 1.0),
        _cand("fixed_2", "search_alerts", {"source_ip": _src(state), "exclude_alert_id": state["alert_id"], "limit": 50}, "Fixed baseline query 2: alerts for source", "baseline", 1.0),
        _cand("fixed_3", "map_attack_to_mitre", {"attack_type": state["alert"]["attack_type"]}, "Fixed baseline query 3: ATT&CK mapping", "baseline", 1.0),
    ]
