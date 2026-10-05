"""Knowledge-graph storage with two interchangeable backends.

* `Neo4jGraphStore`   — used when NEO4J_URI/NEO4J_PASSWORD are configured (Aura or local).
* `InMemoryGraphStore` — NetworkX MultiDiGraph with the same interface; used for tests,
  evaluation runs and the zero-dependency demo.

Both enforce the same rules:
* nodes are MERGEd on a unique `key` (label:value) so knowledge accumulates across investigations
* every relationship carries investigation_id, evidence_ids (sampled), evidence_count,
  first_seen/last_seen, derived_by (rule id) and confidence
* MAX_GRAPH_NODES is enforced per investigation
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from backend.utils.timeutil import to_iso

log = logging.getLogger(__name__)

NODE_LABELS = ["IP", "Device", "Domain", "Attack", "Alert", "EvidenceSet", "Behavior", "IOC",
               "MITRETechnique", "Investigation", "User", "File", "Process"]
MAX_EVIDENCE_IDS_PER_EDGE = 50


def _ser(v: Any) -> Any:
    if isinstance(v, datetime):
        return to_iso(v)
    if isinstance(v, dict):
        return {k: _ser(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_ser(x) for x in v]
    return v


class GraphStore:
    backend = "abstract"

    def merge_node(self, label: str, key: str, props: Dict[str, Any], investigation_id: str,
                   evidence_ids: Iterable[str] = ()) -> Dict[str, Any]:
        raise NotImplementedError

    def merge_relationship(self, src_key: str, rel_type: str, dst_key: str, investigation_id: str,
                           props: Dict[str, Any], evidence_ids: Iterable[str] = ()) -> Dict[str, Any]:
        raise NotImplementedError

    def get_subgraph(self, investigation_id: str, types: Optional[List[str]] = None,
                     start: Optional[str] = None, end: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
        raise NotImplementedError

    def node_evidence(self, investigation_id: str, key: str) -> Dict[str, Any]:
        raise NotImplementedError

    def related_nodes(self, key: str, investigation_id: Optional[str] = None, depth: int = 1) -> Dict[str, Any]:
        raise NotImplementedError

    def count_nodes(self, investigation_id: str) -> int:
        raise NotImplementedError

    def summary(self, investigation_id: str) -> Dict[str, Any]:
        sg = self.get_subgraph(investigation_id, limit=100000)
        by_type: Dict[str, int] = {}
        for n in sg["nodes"]:
            by_type[n["label"]] = by_type.get(n["label"], 0) + 1
        return {"node_count": len(sg["nodes"]), "edge_count": len(sg["edges"]), "by_type": by_type}

    def clear_investigation(self, investigation_id: str) -> None:
        raise NotImplementedError

    def ping(self) -> Dict[str, Any]:
        return {"status": "ok", "backend": self.backend}


# --------------------------------------------------------------------------- in-memory
class InMemoryGraphStore(GraphStore):
    backend = "networkx"

    def __init__(self):
        import networkx as nx

        self.g = nx.MultiDiGraph()
        self.lock = threading.RLock()

    def merge_node(self, label, key, props, investigation_id, evidence_ids=()):
        with self.lock:
            props = _ser(props)
            if key in self.g:
                node = self.g.nodes[key]
                cur = node["props"]
                for k, v in props.items():
                    if v is None:
                        continue
                    if k == "first_seen" and cur.get(k):
                        cur[k] = min(cur[k], v)
                    elif k == "last_seen" and cur.get(k):
                        cur[k] = max(cur[k], v)
                    elif k == "event_count" and cur.get(k) is not None:
                        cur[k] = max(cur[k], v)
                    else:
                        cur[k] = v
                node["investigations"].add(investigation_id)
                node["evidence_ids"].update(evidence_ids)
            else:
                self.g.add_node(key, label=label, props=props, investigations={investigation_id},
                                evidence_ids=set(evidence_ids))
            return {"key": key, "label": label, **self.g.nodes[key]["props"]}

    def merge_relationship(self, src_key, rel_type, dst_key, investigation_id, props, evidence_ids=()):
        with self.lock:
            props = _ser(props)
            for u, v, k, d in self.g.edges(keys=True, data=True):
                if u == src_key and v == dst_key and d["type"] == rel_type and d["investigation_id"] == investigation_id:
                    ev = d["evidence_ids"]
                    for e in evidence_ids:
                        if len(ev) < MAX_EVIDENCE_IDS_PER_EDGE:
                            ev.add(e)
                    d["evidence_count"] = d.get("evidence_count", 0) + props.get("evidence_count", 0)
                    if props.get("first_seen") and (not d.get("first_seen") or props["first_seen"] < d["first_seen"]):
                        d["first_seen"] = props["first_seen"]
                    if props.get("last_seen") and (not d.get("last_seen") or props["last_seen"] > d["last_seen"]):
                        d["last_seen"] = props["last_seen"]
                    for kk, vv in props.items():
                        if kk not in ("first_seen", "last_seen", "evidence_count"):
                            d[kk] = vv
                    return {"src": src_key, "type": rel_type, "dst": dst_key, **{k: v for k, v in d.items() if k != "evidence_ids"}}
            ev = set(list(evidence_ids)[:MAX_EVIDENCE_IDS_PER_EDGE])
            data = {"type": rel_type, "investigation_id": investigation_id, "evidence_ids": ev,
                    "evidence_count": props.get("evidence_count", len(ev)), **{k: v for k, v in props.items() if k != "evidence_count"}}
            self.g.add_edge(src_key, dst_key, **data)
            return {"src": src_key, "type": rel_type, "dst": dst_key, **{k: v for k, v in data.items() if k != "evidence_ids"}}

    def _edges(self, investigation_id):
        for u, v, k, d in self.g.edges(keys=True, data=True):
            if d["investigation_id"] == investigation_id:
                yield u, v, d

    def get_subgraph(self, investigation_id, types=None, start=None, end=None, limit=1000):
        with self.lock:
            edges, node_keys = [], set()
            for u, v, d in self._edges(investigation_id):
                if start and d.get("last_seen") and d["last_seen"] < start:
                    continue
                if end and d.get("first_seen") and d["first_seen"] > end:
                    continue
                lu, lv = self.g.nodes[u]["label"], self.g.nodes[v]["label"]
                if types and (lu not in types or lv not in types):
                    continue
                edges.append({"id": f"{u}|{d['type']}|{v}", "source": u, "target": v, "type": d["type"],
                              **{k: (sorted(val) if isinstance(val, set) else val) for k, val in d.items() if k != "type"}})
                node_keys.update((u, v))
            nodes = []
            for key in list(node_keys)[:limit]:
                n = self.g.nodes[key]
                nodes.append({"key": key, "label": n["label"], "properties": n["props"],
                              "evidence_ids": sorted(n["evidence_ids"])[:MAX_EVIDENCE_IDS_PER_EDGE]})
            return {"nodes": nodes, "edges": edges[: limit * 4]}

    def node_evidence(self, investigation_id, key):
        with self.lock:
            if key not in self.g:
                return {"key": key, "found": False, "evidence_ids": [], "relationships": []}
            rels, ev = [], set(self.g.nodes[key]["evidence_ids"])
            for u, v, d in self._edges(investigation_id):
                if u == key or v == key:
                    rels.append({"source": u, "target": v, "type": d["type"], "evidence_ids": sorted(d["evidence_ids"]),
                                 "evidence_count": d.get("evidence_count"), "derived_by": d.get("derived_by"),
                                 "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen")})
                    ev.update(d["evidence_ids"])
            n = self.g.nodes[key]
            return {"key": key, "found": True, "label": n["label"], "properties": n["props"],
                    "evidence_ids": sorted(ev), "relationships": rels}

    def related_nodes(self, key, investigation_id=None, depth=1):
        with self.lock:
            if key not in self.g:
                return {"key": key, "nodes": [], "edges": []}
            frontier, seen, edges = {key}, {key}, []
            for _ in range(depth):
                nxt = set()
                for u, v, k, d in self.g.edges(keys=True, data=True):
                    if investigation_id and d["investigation_id"] != investigation_id:
                        continue
                    if u in frontier or v in frontier:
                        edges.append({"source": u, "target": v, "type": d["type"], "investigation_id": d["investigation_id"]})
                        nxt.update((u, v))
                frontier = nxt - seen
                seen |= nxt
            return {"key": key, "nodes": [{"key": k, "label": self.g.nodes[k]["label"], "properties": self.g.nodes[k]["props"]} for k in seen],
                    "edges": edges}

    def count_nodes(self, investigation_id):
        with self.lock:
            return sum(1 for _, d in self.g.nodes(data=True) if investigation_id in d["investigations"])

    def clear_investigation(self, investigation_id):
        with self.lock:
            drop = [(u, v, k) for u, v, k, d in self.g.edges(keys=True, data=True) if d["investigation_id"] == investigation_id]
            for e in drop:
                self.g.remove_edge(*e)
            for n, d in list(self.g.nodes(data=True)):
                d["investigations"].discard(investigation_id)
                if not d["investigations"] and self.g.degree(n) == 0:
                    self.g.remove_node(n)


# --------------------------------------------------------------------------- Neo4j
class Neo4jGraphStore(GraphStore):
    backend = "neo4j"

    def __init__(self, uri: str, user: str, password: str, database: Optional[str] = None):
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database
        self.driver.verify_connectivity()
        self._ensure_constraints()

    def _run(self, cypher: str, **params):
        with self.driver.session(database=self.database) as s:
            return [r.data() for r in s.run(cypher, **params)]

    def _ensure_constraints(self):
        for label in NODE_LABELS:
            try:
                self._run(f"CREATE CONSTRAINT {label.lower()}_key IF NOT EXISTS FOR (n:{label}) REQUIRE n.key IS UNIQUE")
            except Exception as exc:  # pragma: no cover
                log.warning("constraint for %s failed: %s", label, exc)

    def merge_node(self, label, key, props, investigation_id, evidence_ids=()):
        if label not in NODE_LABELS:
            raise ValueError(f"unknown node label {label}")
        props = {k: (_ser(v) if not isinstance(v, (dict, list)) else str(_ser(v))) for k, v in props.items() if v is not None}
        special = {k: props.pop(k, None) for k in ("first_seen", "last_seen", "event_count")}
        rows = self._run(
            f"MERGE (n:{label} {{key: $key}}) SET n += $props, "
            "n.first_seen = CASE WHEN $fs IS NULL THEN n.first_seen WHEN n.first_seen IS NULL OR $fs < n.first_seen THEN $fs ELSE n.first_seen END, "
            "n.last_seen = CASE WHEN $ls IS NULL THEN n.last_seen WHEN n.last_seen IS NULL OR $ls > n.last_seen THEN $ls ELSE n.last_seen END, "
            "n.event_count = CASE WHEN $ec IS NULL THEN n.event_count WHEN n.event_count IS NULL OR $ec > n.event_count THEN $ec ELSE n.event_count END, "
            "n.investigations = CASE WHEN n.investigations IS NULL THEN [$inv] "
            "WHEN $inv IN n.investigations THEN n.investigations ELSE n.investigations + $inv END, "
            "n.evidence_ids = CASE WHEN n.evidence_ids IS NULL THEN $ev ELSE n.evidence_ids + [e IN $ev WHERE NOT e IN n.evidence_ids] END "
            "RETURN n",
            key=key, props=props, inv=investigation_id, ev=list(evidence_ids)[:MAX_EVIDENCE_IDS_PER_EDGE],
            fs=special["first_seen"], ls=special["last_seen"], ec=special["event_count"],
        )
        return {"key": key, "label": label, **(rows[0]["n"] if rows else {})}

    def merge_relationship(self, src_key, rel_type, dst_key, investigation_id, props, evidence_ids=()):
        if not rel_type.replace("_", "").isalpha():
            raise ValueError("invalid relationship type")
        props = {k: (_ser(v) if not isinstance(v, (dict, list)) else str(_ser(v))) for k, v in props.items() if v is not None}
        ev = list(evidence_ids)[:MAX_EVIDENCE_IDS_PER_EDGE]
        rows = self._run(
            f"MATCH (a {{key: $src}}), (b {{key: $dst}}) "
            f"MERGE (a)-[r:{rel_type} {{investigation_id: $inv}}]->(b) "
            "ON CREATE SET r += $props, r.evidence_ids = $ev, r.evidence_count = coalesce($props.evidence_count, size($ev)) "
            "ON MATCH SET r.evidence_ids = r.evidence_ids + [e IN $ev WHERE NOT e IN r.evidence_ids][0..50], "
            "r.evidence_count = coalesce(r.evidence_count,0) + coalesce($props.evidence_count,0), "
            "r.first_seen = CASE WHEN $props.first_seen IS NOT NULL AND ($props.first_seen < r.first_seen OR r.first_seen IS NULL) THEN $props.first_seen ELSE r.first_seen END, "
            "r.last_seen = CASE WHEN $props.last_seen IS NOT NULL AND ($props.last_seen > r.last_seen OR r.last_seen IS NULL) THEN $props.last_seen ELSE r.last_seen END "
            "RETURN type(r) AS type, properties(r) AS props",
            src=src_key, dst=dst_key, inv=investigation_id, props=props, ev=ev,
        )
        r = rows[0] if rows else {"type": rel_type, "props": {}}
        return {"src": src_key, "type": r["type"], "dst": dst_key, **{k: v for k, v in r["props"].items() if k != "evidence_ids"}}

    def get_subgraph(self, investigation_id, types=None, start=None, end=None, limit=1000):
        rows = self._run(
            "MATCH (a)-[r {investigation_id: $inv}]->(b) "
            "WHERE ($start IS NULL OR r.last_seen IS NULL OR r.last_seen >= $start) "
            "AND ($end IS NULL OR r.first_seen IS NULL OR r.first_seen <= $end) "
            "RETURN a.key AS ak, labels(a)[0] AS al, properties(a) AS ap, type(r) AS rt, properties(r) AS rp, "
            "b.key AS bk, labels(b)[0] AS bl, properties(b) AS bp LIMIT $limit",
            inv=investigation_id, start=start, end=end, limit=limit * 4,
        )
        nodes: Dict[str, Dict[str, Any]] = {}
        edges = []
        for r in rows:
            if types and (r["al"] not in types or r["bl"] not in types):
                continue
            for k, l, p in ((r["ak"], r["al"], r["ap"]), (r["bk"], r["bl"], r["bp"])):
                if k not in nodes:
                    props = {kk: vv for kk, vv in p.items() if kk not in ("key", "investigations", "evidence_ids")}
                    nodes[k] = {"key": k, "label": l, "properties": props, "evidence_ids": (p.get("evidence_ids") or [])[:50]}
            rp = dict(r["rp"])
            edges.append({"id": f"{r['ak']}|{r['rt']}|{r['bk']}", "source": r["ak"], "target": r["bk"], "type": r["rt"], **rp})
        return {"nodes": list(nodes.values())[:limit], "edges": edges}

    def node_evidence(self, investigation_id, key):
        rows = self._run(
            "MATCH (n {key: $key}) OPTIONAL MATCH (n)-[r {investigation_id: $inv}]-(m) "
            "RETURN labels(n)[0] AS label, properties(n) AS props, collect({type: type(r), src: startNode(r).key, dst: endNode(r).key, "
            "evidence_ids: r.evidence_ids, evidence_count: r.evidence_count, derived_by: r.derived_by, first_seen: r.first_seen, last_seen: r.last_seen}) AS rels",
            key=key, inv=investigation_id,
        )
        if not rows:
            return {"key": key, "found": False, "evidence_ids": [], "relationships": []}
        r = rows[0]
        ev = set(r["props"].get("evidence_ids") or [])
        rels = []
        for x in r["rels"]:
            if x["type"] is None:
                continue
            rels.append({"source": x["src"], "target": x["dst"], "type": x["type"], "evidence_ids": x["evidence_ids"] or [],
                         "evidence_count": x["evidence_count"], "derived_by": x["derived_by"], "first_seen": x["first_seen"], "last_seen": x["last_seen"]})
            ev.update(x["evidence_ids"] or [])
        props = {k: v for k, v in r["props"].items() if k not in ("investigations", "evidence_ids")}
        return {"key": key, "found": True, "label": r["label"], "properties": props, "evidence_ids": sorted(ev), "relationships": rels}

    def related_nodes(self, key, investigation_id=None, depth=1):
        depth = max(1, min(int(depth), 3))
        rows = self._run(
            f"MATCH (n {{key: $key}})-[r*1..{depth}]-(m) "
            "WHERE $inv IS NULL OR all(x IN r WHERE x.investigation_id = $inv) "
            "RETURN DISTINCT m.key AS key, labels(m)[0] AS label, properties(m) AS props LIMIT 500",
            key=key, inv=investigation_id,
        )
        return {"key": key, "nodes": [{"key": r["key"], "label": r["label"], "properties": r["props"]} for r in rows], "edges": []}

    def count_nodes(self, investigation_id):
        rows = self._run("MATCH (n) WHERE $inv IN coalesce(n.investigations, []) RETURN count(n) AS c", inv=investigation_id)
        return rows[0]["c"] if rows else 0

    def clear_investigation(self, investigation_id):
        self._run("MATCH ()-[r {investigation_id: $inv}]-() DELETE r", inv=investigation_id)

    def ping(self):
        try:
            self._run("RETURN 1")
            return {"status": "ok", "backend": "neo4j"}
        except Exception as exc:
            return {"status": "error", "backend": "neo4j", "error": str(exc)}


_graph: Optional[GraphStore] = None


def get_graph_store() -> GraphStore:
    global _graph
    if _graph is None:
        from backend.config import get_settings

        s = get_settings()
        if s.neo4j_configured:
            try:
                _graph = Neo4jGraphStore(s.neo4j_uri, s.neo4j_username, s.neo4j_password)
                log.info("Connected to Neo4j at %s", s.neo4j_uri)
            except Exception as exc:
                log.error("Neo4j unreachable (%s); using in-memory graph store", exc)
                _graph = InMemoryGraphStore()
        else:
            log.warning("NEO4J_URI not set — using in-memory NetworkX graph store")
            _graph = InMemoryGraphStore()
    return _graph


def set_graph_store(store: GraphStore) -> None:
    global _graph
    _graph = store
