"""Run the offline pipeline (demo mode if no dataset) and one adaptive investigation end to end.

    python scripts/smoke_investigation.py [--attack "Port Scan"] [--mode adaptive|baseline]
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.config import get_settings  # noqa: E402
from backend.services.gemini import GeminiClient  # noqa: E402
from backend.services.graph_store import InMemoryGraphStore  # noqa: E402
from backend.services.mitre import MitreService  # noqa: E402
from backend.services.mongo import DocumentStore  # noqa: E402
from backend.services.runner import InvestigationRunner  # noqa: E402
from ml.pipeline import run_all  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="Port Scan")
    ap.add_argument("--mode", default="adaptive")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)
    s = get_settings()
    store = DocumentStore(s).connect()
    run_all(s, store, fast=True)
    runner = InvestigationRunner(s, store, InMemoryGraphStore(), GeminiClient(s), MitreService())
    a = store["alerts"].find_one({"attack_type": args.attack})
    print("ALERT:", a["_id"], a["attack_type"], a["source_ip"], a["destination_ips"], a["first_seen"])
    t = time.time()
    inv = runner.create(a["_id"], mode=args.mode)
    doc = runner.run_sync(inv["_id"])
    print("STATUS:", doc["status"], "elapsed", round(time.time() - t, 2), "s")
    if doc["status"] == "failed":
        print(doc.get("error"))
        print(doc.get("traceback"))
        return 1
    st = doc["state"]
    print("termination:", st["termination_reason"], "| steps:", st["budget"]["steps_used"], "| evidence:", len(st["evidence"]), "| graph:", st["graph_state"])
    print("sufficiency:", st["sufficiency"])
    print("\n--- AGENT LOG ---")
    for x in st["agent_log"]:
        print(f"step {x['step']:>2} [{x['agent'][:22]:22}] {x['title'][:58]:58} | {x['detail'][:120]}")
    print("\n--- CHAIN ---")
    for sg in st["attack_chain"]["stages"]:
        print(f"  stage {sg['stage']}: {sg['attack_type']:24} {sg['first_seen']} -> {sg['last_seen']} flows={sg['event_count']} src={sg['sources']} tgt={sg['targets']} ev={len(sg['evidence_ids'])}")
    print("relationships:", [(r["from_stage"], r["to_stage"], r["link_strength"], round(r["gap_seconds"] or 0)) for r in st["attack_chain"]["relationships"]])
    print("caveats:", st["attack_chain"]["unsupported_gaps"])
    rep = st["final_report"]
    print("\n--- REPORT ---")
    print("title:", rep["sections"]["1_incident_title"])
    print("severity:", rep["sections"]["3_severity"])
    print("claims:", rep["metrics"]["claims"], "validated:", rep["metrics"]["claims_validated"])
    print("mitre:", [(m["attack_type"], m["technique_id"]) for m in rep["sections"]["11_mitre_mapping"]])
    print("narrative:\n", rep["sections"]["13_ai_attack_narrative"]["text"][:1500])
    print("\nlimitations:", rep["sections"]["15_investigation_limitations"][:4])
    gt = store["scenarios"].find_one({"sources": a["source_ip"]})
    print("\nGROUND TRUTH (evaluation only):", gt["name"] if gt else None, [(x["label"], x["event_count"]) for x in gt["stages"]] if gt else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
