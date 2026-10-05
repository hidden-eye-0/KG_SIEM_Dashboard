"""Run the paired adaptive-vs-baseline comparison from the command line.

    python scripts/run_evaluation.py --n 10 [--name my-run] [--policies heuristic,llm]

Prints the summary table and writes JSON to data/reports/evaluation_<run_id>.json.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.config import get_settings
from backend.deps import build_container


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6, help="number of alerts (round-robin over categories)")
    ap.add_argument("--name", default="cli")
    ap.add_argument("--policies", default=None, help="comma-separated adaptive policies to compare against the baseline")
    args = ap.parse_args()
    c = build_container(get_settings())
    if c.store["alerts"].estimated_document_count() == 0:
        from ml.pipeline import run_all

        run_all(c.settings, c.store, fast=True)
    policies = args.policies.split(",") if args.policies else None
    run = c.evaluator.run_comparison(n_alerts=args.n, policies=policies, name=args.name)
    out = Path(c.settings.reports_dir) / f"evaluation_{run['_id']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(run, indent=1, default=str))
    arms = list(run["summary"].keys())
    keys = ["n", "steps", "db_queries", "events_retrieved", "llm_calls", "evidence_precision", "evidence_recall",
            "stage_recall", "stage_precision", "chain_complete_rate", "claim_evidence_rate", "grounding_pass_rate", "latency_ms"]
    print(f"\nrun {run['_id']} — {len(run['alert_ids'])} alerts\n")
    print(f"{'metric':28s}" + "".join(f"{a:>16s}" for a in arms))
    for k in keys:
        print(f"{k:28s}" + "".join(f"{str(run['summary'][a].get(k, '—'))[:14]:>16s}" for a in arms))
    for n in run.get("notes", []):
        print(" -", n)
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
