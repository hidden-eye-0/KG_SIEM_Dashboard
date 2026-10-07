"""Contract tests for the deterministic parts of the framework (no network, no LLM, no real DB).

They exercise, in-process:
  * label scope (all Mirai excluded, in-scope list stable),
  * the fast demo pipeline (synthetic flows -> models -> events -> alerts) into mongomock,
  * ground-truth isolation at the tool layer,
  * one adaptive and one baseline investigation end-to-end,
  * traceability: every report claim resolves to evidence ids that exist,
  * graph determinism: every node/edge carries evidence ids,
  * safeguards: hard budgets are respected and recorded,
  * grounding validator rejects invented ids / IPs,
  * threat-intel gate never sends private/documentation IPs upstream,
  * markdown / pdf report rendering,
  * the FastAPI surface via TestClient.

The suite takes ~40-60 s on a 2-vCPU machine because it trains small models once.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("AUTO_SEED_DEMO", "false")
os.environ.setdefault("INVESTIGATION_POLICY", "heuristic")
os.environ.setdefault("GEMINI_API_KEY", "")
os.environ.setdefault("MONGODB_URI", "")
os.environ.setdefault("NEO4J_URI", "")
os.environ.setdefault("DATASET_DIR", str(Path(__file__).resolve().parents[2] / "data" / "raw"))

from backend.config import get_settings  # noqa: E402
from backend.deps import build_container  # noqa: E402
from backend.services.graph_store import InMemoryGraphStore, set_graph_store  # noqa: E402
from backend.services.mongo import DocumentStore, set_store  # noqa: E402
from ml.preprocessing.labels import EXPECTED_LABELS, in_scope_labels  # noqa: E402


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def container():
    settings = get_settings()
    store = DocumentStore(settings).connect()  # mongomock because MONGODB_URI is empty
    set_store(store)
    set_graph_store(InMemoryGraphStore())
    c = build_container(settings)
    from ml.pipeline import run_all

    summary = run_all(settings, store, fast=True)
    c.seed_status = {"status": "completed", **{k: v for k, v in summary.items() if k != "profiles"}}
    return c


@pytest.fixture(scope="module")
def adaptive(container):
    alert = container.store["alerts"].find_one({"severity": {"$in": ["high", "medium"]}})
    assert alert, "demo pipeline produced no medium/high alert"
    doc = container.runner.create(alert["_id"], mode="adaptive", policy="heuristic")
    return container.runner.run_sync(doc["_id"])


@pytest.fixture(scope="module")
def baseline(container, adaptive):
    doc = container.runner.create(adaptive["alert_id"], mode="baseline")
    return container.runner.run_sync(doc["_id"])


# --------------------------------------------------------------------------- label scope
def test_label_scope_excludes_every_mirai_and_keeps_23_classes():
    scope = [l.raw_label for l in in_scope_labels()]
    assert len(scope) == 23
    assert not any(l.lower().startswith("mirai") for l in scope)
    assert "BrowserHijacking" not in scope  # decision D5
    assert {"BenignTraffic", "DDoS-ICMP_Flood", "Recon-PortScan", "DictionaryBruteForce", "MITM-ArpSpoofing", "DNS_Spoofing"} <= set(scope)
    assert set(scope) <= {l.raw_label for l in EXPECTED_LABELS}
    assert all(l.exclusion_reason for l in EXPECTED_LABELS if not l.in_scope)


# --------------------------------------------------------------------------- pipeline
def test_demo_pipeline_is_marked_synthetic_and_populates_store(container):
    s = container.store
    assert s["security_events"].estimated_document_count() > 1000
    assert s["alerts"].estimated_document_count() > 10
    card = s["models"].find_one({}, sort=[("created_at", -1)])
    assert card and card["data_source"] == "synthetic_demo"
    assert card["primary_model"] in card["models"]
    assert set(card["classes"]) == {l.raw_label for l in in_scope_labels()}
    ev = s["security_events"].find_one({})
    assert ev["context"]["provenance"] == "synthesized"
    assert "ground_truth" in ev  # stored for evaluation ...


def test_tool_layer_strips_ground_truth(container):
    res = container.runner.repo.search_security_events({}, None, None, 50)
    assert res["count"] > 0
    for r in res["records"]:
        assert "ground_truth" not in r  # ... but never leaves the repository
        assert "features" in r and "prediction" in r


def test_alert_documents_use_evidence_phrasing(container):
    a = container.store["alerts"].find_one({})
    assert a["provenance"] == "synthesized"
    assert a["behavioral_evidence"]["top_features"]
    stmt = (a.get("profile") or {}).get("profile_statement", "")
    assert "prove" not in stmt.lower()
    assert "associated with" in stmt.lower() or "evidence" in stmt.lower()


# --------------------------------------------------------------------------- investigation
def test_adaptive_investigation_completes_within_budgets(container, adaptive):
    st = adaptive["state"]
    b = st["budget"]
    assert adaptive["status"] == "completed"
    assert st["investigation_step"] <= b["max_steps"]
    assert b["llm_calls_used"] == 0  # heuristic policy: no LLM
    assert st["graph_state"]["node_count"] <= container.settings.max_graph_nodes
    for e in st["evidence"]:
        assert e["record_count"] <= container.settings.max_events_per_query
    assert st["termination_reason"] in {"max_steps", "timeout", "no_candidates", "sufficient", "diminishing_returns", "budget"}
    assert adaptive["metrics"]["steps"] >= 2


def test_adaptive_is_state_dependent_not_fixed(container, adaptive, baseline):
    """The adaptive loop must choose queries from the gap table; the baseline runs a fixed plan."""
    a_tools = [e["tool"] for e in adaptive["state"]["evidence"]]
    b_tools = [e["tool"] for e in baseline["state"]["evidence"]]
    assert baseline["policy"] == "fixed" and adaptive["policy"] == "heuristic"
    assert len(b_tools) == 3, b_tools  # fixed three-query baseline
    decisions = [a for a in adaptive["state"]["agent_log"] if a["node"] == "decide_action"]
    assert decisions, "no decision trace recorded"
    assert all(d.get("detail") for d in decisions)  # each decision carries a rationale
    assert adaptive["state"]["missing_evidence"], "gap table missing"


def test_every_graph_element_is_traceable(container, adaptive):
    inv = adaptive["_id"]
    sg = container.graph.get_subgraph(inv, limit=2000)
    assert sg["nodes"] and sg["edges"]
    known_ev = {e["evidence_id"] for e in adaptive["state"]["evidence"]}
    for e in sg["edges"]:
        assert e["derived_by"], e
        assert e.get("evidence_ids") is not None
        for eid in e["evidence_ids"]:
            assert eid.startswith(("evd_", "alr_", "inv_", "evt_")), eid
            if eid.startswith("evd_"):
                assert eid in known_ev
    for n in sg["nodes"]:
        assert n["label"] in {"Investigation", "Alert", "IP", "Device", "Attack", "Behavior", "EvidenceSet", "IOC", "MITRETechnique"}


def test_report_claims_resolve_to_existing_evidence(container, adaptive):
    inv = adaptive["_id"]
    rep = container.store["reports"].find_one({"investigation_id": inv})
    assert rep and rep["claims"]
    known_ev = {e["evidence_id"] for e in adaptive["state"]["evidence"]}
    for c in rep["claims"]:
        assert c["evidence_ids"], c["text"]
        for eid in c["evidence_ids"]:
            if eid.startswith("evd_"):
                assert eid in known_ev
            elif eid.startswith("evt_"):
                assert container.store["security_events"].find_one({"_id": eid}, {"_id": 1})
            elif eid.startswith("alr_"):
                assert container.store["alerts"].find_one({"_id": eid}, {"_id": 1})
    secs = rep["sections"]
    assert len(secs) == 15
    assert secs["13_ai_attack_narrative"]["generated_by"].split(" ")[0] in {"template", "gemini"}
    assert "Insufficient evidence" in json.dumps(secs) or "Not available" in json.dumps(secs)


def test_chain_is_not_forced_into_kill_chain(container, adaptive):
    chain = adaptive["state"]["attack_chain"]
    assert chain["stage_count"] >= 1
    assert all(s["evidence_ids"] or s["evidence_set_ids"] for s in chain["stages"])
    for r in chain["relationships"]:
        assert r["gap_seconds"] is None or r["gap_seconds"] >= 0
        assert r["link_strength"] in {"strong", "moderate", "weak"}
    if chain["stage_count"] == 1:
        assert chain["unsupported_gaps"]


# --------------------------------------------------------------------------- grounding validator
def test_grounding_validator_rejects_invented_ids_and_ips(adaptive):
    from backend.agents.agents import validate_grounding

    st = adaptive["state"]
    real = st["evidence"][0]["evidence_id"]
    ok = validate_grounding(f"Flows from {st['alert']['source_ip']} [{real}].", st)
    assert ok["passed"]
    bad = validate_grounding(f"Attacker 8.8.8.8 exfiltrated data [evd_01FAKEFAKEFAKEFAKEFAKEFAK] [{real}].", st)
    assert not bad["passed"]
    assert bad["unknown_evidence_ids"] == ["evd_01FAKEFAKEFAKEFAKEFAKEFAK"]
    assert "8.8.8.8" in bad["unknown_ips"]
    assert bad["forbidden_phrases"] == ["exfiltrated"]


# --------------------------------------------------------------------------- threat intel gate
def test_threat_intel_never_queries_private_or_documentation_ips(container, monkeypatch):
    calls = []
    import httpx

    def boom(*a, **k):
        calls.append(a)
        raise AssertionError("network call attempted")

    monkeypatch.setattr(httpx, "get", boom, raising=False)
    monkeypatch.setattr(httpx.Client, "get", boom, raising=False)
    for ip in ("192.168.10.11", "10.0.0.5", "203.0.113.24", "198.51.100.7"):
        r = container.ti.lookup(ip)
        for prov in ("virustotal", "otx"):
            assert r[prov]["status"] in {"private_address", "not_configured", "documentation_address", "skipped"}, r[prov]
    assert not calls


# --------------------------------------------------------------------------- reports
def test_markdown_and_pdf_rendering(container, adaptive, tmp_path):
    from backend.services.reports import report_to_markdown, report_to_pdf

    rep = container.store["reports"].find_one({"investigation_id": adaptive["_id"]})
    md = report_to_markdown(rep)
    assert md.startswith("#") and "evd_" in md
    assert "Insufficient evidence" in md or "Not available" in md
    out = tmp_path / "report.pdf"
    report_to_pdf(rep, out)
    assert out.exists() and out.stat().st_size > 1000


# --------------------------------------------------------------------------- API surface
def test_api_surface(container, adaptive):
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        h = client.get("/api/health").json()
        assert h["status"] in {"ok", "degraded"}
        assert h["mongo"]["backend"] == "mongomock" and h["graph"]["backend"] == "networkx"
        cfg = client.get("/api/config").json()
        assert "gemini_api_key" not in json.dumps(cfg).lower() or cfg.get("gemini_api_key") in (None, "")
        assert cfg["dataset_placeholder"] is True
        assert client.get("/api/alerts?page_size=5").json()["items"]
        assert client.get("/api/events/summary").json()["data_source"] == "synthetic_demo"
        inv = client.get(f"/api/investigations/{adaptive['_id']}?include_state=true").json()
        assert inv["status"] == "completed" and "ground_truth" not in json.dumps(inv)
        node = client.get(f"/api/graph/{adaptive['_id']}/node", params={"key": f"IP:{adaptive['alert_summary']['source_ip']}", "records": 5}).json()
        assert node["found"] and node["relationships"]
        g = client.get(f"/api/evaluation/grounding/{adaptive['_id']}").json()
        assert g["claims_fully_resolved"] == g["claims_total"]
        assert client.get(f"/api/reports/{adaptive['_id']}/markdown").status_code == 200
        assert client.get("/api/mitre/techniques").json()["mappings"]
        r = client.post("/api/investigations", json={"alert_id": adaptive["alert_id"], "mode": "baseline", "autostart": False})
        assert r.status_code == 201 and r.json()["policy"] == "fixed"

        ingest = client.post(
            "/api/ingest",
            json={
                "model_version": "integration-test",
                "source": "contract-test",
                "events": [
                    {
                        "timestamp": "2026-10-07T01:00:00Z",
                        "source_ip": "203.0.113.44",
                        "destination_ip": "192.0.2.44",
                        "device_id": "device-contract-01",
                        "device_type": "iot",
                        "protocol": "ICMP",
                        "log_source": "contract-test",
                        "features": {"Rate": 50.0, "ICMP": 1.0},
                        "prediction": {
                            "label": "DDoS-ICMP_Flood",
                            "attack_type": "DDoS ICMP Flood",
                            "category": "DDoS",
                            "confidence": 0.99,
                            "model": "integration-test",
                        },
                    }
                ],
            },
        )
        assert ingest.status_code == 202, ingest.text
        body = ingest.json()
        assert body["status"] == "accepted"
        assert body["events_ingested"] == 1
        assert body["alerts_created"] == 1
        assert body["provenance"] == "ingested"

        live = client.get("/api/events", params={"source_ip": "203.0.113.44", "page_size": 5}).json()
        assert live["items"] and "ground_truth" not in json.dumps(live["items"])
        assert live["items"][0]["context"]["provenance"] == "ingested"

        bad = client.post(
            "/api/ingest",
            json={
                "model_version": "integration-test",
                "events": [{
                    "timestamp": "2026-10-07T01:00:00Z",
                    "source_ip": "203.0.113.45",
                    "destination_ip": "192.0.2.45",
                    "prediction": {
                        "label": "DDoS-ICMP_Flood",
                        "attack_type": "DDoS ICMP Flood",
                        "category": "DDoS",
                        "confidence": 0.99,
                    },
                    "ground_truth": {"label": "should-never-be-accepted"},
                }],
            },
        )
        assert bad.status_code == 422
