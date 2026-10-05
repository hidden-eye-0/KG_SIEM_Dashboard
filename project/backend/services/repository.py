"""Security-event evidence repository.

This is the *only* module that queries `security_events` for the investigation.
It enforces the safeguards required by the brief inside the data layer so that no
agent can bypass them:

* `limit` is capped at MAX_EVENTS_PER_QUERY
* time windows are clamped to MAX_TIME_WINDOW_SECONDS
* the `ground_truth` sub-document (dataset label, scenario id) is NEVER returned
* every query reports total_matched so truncation is visible to the analyst
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from backend.config import Settings
from backend.services.mongo import DocumentStore
from backend.utils.timeutil import clamp_window, parse_dt

# Fields exposed to agents / API (ground truth deliberately absent)
EVENT_PROJECTION = {"ground_truth": 0}

AUTH_PROTOCOL_INDICATORS = ["SSH", "Telnet"]
DNS_INDICATOR = "DNS"


def strip_ground_truth(doc: Dict[str, Any]) -> Dict[str, Any]:
    if doc is None:
        return doc
    doc.pop("ground_truth", None)
    return doc


class EventQueryResult(dict):
    """dict with keys: records, count, total_matched, truncated, latency_ms, window."""


class EvidenceRepository:
    def __init__(self, store: DocumentStore, settings: Settings):
        self.store = store
        self.settings = settings
        self.events = store["security_events"]
        self.alerts = store["alerts"]

    # ------------------------------------------------------------------ internals
    def _cap(self, limit: Optional[int]) -> int:
        cap = self.settings.max_events_per_query
        if limit is None or limit <= 0:
            return cap
        return min(int(limit), cap)

    def _window(self, start, end) -> tuple[Optional[datetime], Optional[datetime], bool]:
        s, e = parse_dt(start), parse_dt(end)
        if s is None and e is None:
            return None, None, False
        if s is None:
            s = e - timedelta(seconds=self.settings.max_time_window_seconds)
        if e is None:
            e = s + timedelta(seconds=self.settings.max_time_window_seconds)
        s, e, clamped = clamp_window(s, e, self.settings.max_time_window_seconds)
        return s, e, clamped

    def _run(self, query: Dict[str, Any], limit: Optional[int], sort=(("timestamp", 1),),
             start=None, end=None, projection: Optional[dict] = None) -> EventQueryResult:
        t0 = time.perf_counter()
        s, e, clamped = self._window(start, end)
        if s is not None:
            query = {**query, "timestamp": {"$gte": s, "$lte": e}}
        cap = self._cap(limit)
        proj = dict(EVENT_PROJECTION)
        if projection:
            proj = projection  # caller-supplied projection must also exclude ground truth
            proj["ground_truth"] = 0
        cursor = self.events.find(query, proj).sort(list(sort)).limit(cap)
        records = [strip_ground_truth(d) for d in cursor]
        total = self.events.count_documents(query)
        return EventQueryResult(
            records=records,
            count=len(records),
            total_matched=total,
            truncated=total > len(records),
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
            window={"start": s, "end": e, "clamped": clamped},
            query=query,
        )

    # ------------------------------------------------------------------ evidence tools
    def search_security_events(self, filters: Optional[Dict[str, Any]] = None, start=None, end=None,
                               limit: Optional[int] = None) -> EventQueryResult:
        q: Dict[str, Any] = {}
        f = filters or {}
        for key in ("source_ip", "destination_ip", "device_id", "protocol", "log_source"):
            if f.get(key):
                q[key] = f[key]
        if f.get("attack_type"):
            q["prediction.attack_type"] = f["attack_type"]
        if f.get("category"):
            q["prediction.category"] = f["category"]
        if f.get("exclude_attack_type"):
            q["prediction.attack_type"] = {"$ne": f["exclude_attack_type"]}
        if f.get("malicious_only"):
            q["prediction.category"] = {"$ne": "Benign"}
        return self._run(q, limit, start=start, end=end)

    def get_events_by_ip(self, ip: str, role: str = "any", start=None, end=None,
                         limit: Optional[int] = None, exclude_attack_type: Optional[str] = None) -> EventQueryResult:
        if role == "src":
            q: Dict[str, Any] = {"source_ip": ip}
        elif role == "dst":
            q = {"destination_ip": ip}
        else:
            q = {"$or": [{"source_ip": ip}, {"destination_ip": ip}]}
        if exclude_attack_type:
            q["prediction.attack_type"] = {"$ne": exclude_attack_type}
        return self._run(q, limit, start=start, end=end)

    def get_events_by_time_range(self, start, end, filters: Optional[Dict[str, Any]] = None,
                                 limit: Optional[int] = None) -> EventQueryResult:
        return self.search_security_events(filters, start=start, end=end, limit=limit)

    def get_events_by_device(self, device_id: str, start=None, end=None, limit=None) -> EventQueryResult:
        return self._run({"device_id": device_id}, limit, start=start, end=end)

    def get_authentication_events(self, ip: Optional[str] = None, device_id: Optional[str] = None,
                                  start=None, end=None, limit=None) -> EventQueryResult:
        q: Dict[str, Any] = {"$or": [{f"features.{p}": {"$gt": 0}} for p in AUTH_PROTOCOL_INDICATORS]}
        if ip:
            q = {"$and": [q, {"$or": [{"source_ip": ip}, {"destination_ip": ip}]}]}
        if device_id:
            q = {"$and": [q, {"device_id": device_id}]}
        return self._run(q, limit, start=start, end=end)

    def get_network_events(self, ip: Optional[str] = None, protocol: Optional[str] = None,
                           start=None, end=None, limit=None) -> EventQueryResult:
        q: Dict[str, Any] = {}
        if ip:
            q["$or"] = [{"source_ip": ip}, {"destination_ip": ip}]
        if protocol:
            q["protocol"] = protocol
        return self._run(q, limit, start=start, end=end)

    def get_dns_events(self, ip: Optional[str] = None, device_id: Optional[str] = None,
                       start=None, end=None, limit=None) -> EventQueryResult:
        q: Dict[str, Any] = {f"features.{DNS_INDICATOR}": {"$gt": 0}}
        if ip:
            q["$or"] = [{"source_ip": ip}, {"destination_ip": ip}]
        if device_id:
            q["device_id"] = device_id
        return self._run(q, limit, start=start, end=end)

    def get_firewall_events(self, ip: Optional[str] = None, start=None, end=None, limit=None) -> EventQueryResult:
        q: Dict[str, Any] = {"log_source": "firewall"}
        if ip:
            q["$or"] = [{"source_ip": ip}, {"destination_ip": ip}]
        res = self._run(q, limit, start=start, end=end)
        if res["total_matched"] == 0 and self.events.count_documents({"log_source": "firewall"}, limit=1) == 0:
            res["no_source"] = True
        return res

    def get_related_events(self, alert: Dict[str, Any], strategy: str = "same_source",
                           window_seconds: int = 3600, limit=None) -> EventQueryResult:
        first, last = parse_dt(alert["first_seen"]), parse_dt(alert["last_seen"])
        src = alert.get("source_ip")
        dsts = alert.get("destination_ips") or []
        atype = alert.get("attack_type")
        if strategy == "follow_on":
            q: Dict[str, Any] = {"source_ip": src, "prediction.attack_type": {"$ne": atype}}
            return self._run(q, limit, start=last, end=last + timedelta(seconds=window_seconds))
        if strategy == "precursor":
            q = {"source_ip": src, "prediction.attack_type": {"$ne": atype}}
            return self._run(q, limit, start=first - timedelta(seconds=window_seconds), end=first)
        if strategy == "same_target":
            q = {"destination_ip": {"$in": dsts}, "source_ip": {"$ne": src}}
            return self._run(q, limit, start=first - timedelta(seconds=window_seconds),
                             end=last + timedelta(seconds=window_seconds))
        if strategy == "same_pair":
            q = {"source_ip": src, "destination_ip": {"$in": dsts}}
            return self._run(q, limit, start=first - timedelta(seconds=window_seconds),
                             end=last + timedelta(seconds=window_seconds))
        # same_source (default): anything else from the source around the alert
        q = {"source_ip": src}
        return self._run(q, limit, start=first - timedelta(seconds=window_seconds),
                         end=last + timedelta(seconds=window_seconds))

    def get_event_aggregates(self, group_by: str, filters: Optional[Dict[str, Any]] = None,
                             start=None, end=None, top: int = 20) -> Dict[str, Any]:
        """Counts without pulling rows (cheap breadth queries)."""
        t0 = time.perf_counter()
        field_map = {
            "destination_ip": "$destination_ip",
            "source_ip": "$source_ip",
            "attack_type": "$prediction.attack_type",
            "category": "$prediction.category",
            "protocol": "$protocol",
            "device_id": "$device_id",
        }
        if group_by not in field_map:
            raise ValueError(f"unsupported group_by {group_by}")
        q = self.search_security_events(filters, start=start, end=end, limit=1)["query"]
        pipeline = [
            {"$match": q},
            {"$group": {"_id": field_map[group_by], "count": {"$sum": 1},
                        "first_seen": {"$min": "$timestamp"}, "last_seen": {"$max": "$timestamp"}}},
            {"$sort": {"count": -1}},
            {"$limit": int(top)},
        ]
        rows = list(self.events.aggregate(pipeline))
        return {
            "group_by": group_by,
            "buckets": [{"key": r["_id"], "count": r["count"], "first_seen": r["first_seen"],
                         "last_seen": r["last_seen"]} for r in rows],
            "distinct_count": len(rows),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            "query": q,
        }

    def get_events_by_ids(self, ids: Iterable[str], limit: Optional[int] = None) -> List[Dict[str, Any]]:
        ids = list(ids)[: self._cap(limit)]
        return [strip_ground_truth(d) for d in self.events.find({"_id": {"$in": ids}}, EVENT_PROJECTION)]

    # ------------------------------------------------------------------ alerts
    def search_alerts(self, source_ip: Optional[str] = None, destination_ip: Optional[str] = None,
                      category: Optional[str] = None, exclude_alert_id: Optional[str] = None,
                      start=None, end=None, limit: int = 50) -> Dict[str, Any]:
        t0 = time.perf_counter()
        q: Dict[str, Any] = {}
        if source_ip:
            q["source_ip"] = source_ip
        if destination_ip:
            q["destination_ips"] = destination_ip
        if category:
            q["category"] = category
        if exclude_alert_id:
            q["_id"] = {"$ne": exclude_alert_id}
        s, e, _ = self._window(start, end)
        if s is not None:
            q["first_seen"] = {"$gte": s, "$lte": e}
        rows = list(self.alerts.find(q).sort([("first_seen", 1)]).limit(min(limit, 200)))
        return {"records": rows, "count": len(rows), "total_matched": self.alerts.count_documents(q),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "query": q}
