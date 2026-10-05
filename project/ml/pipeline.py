"""End-to-end offline pipeline (Phases 1–6) with two data modes.

    DATASET MODE  : CSV files exist under DATASET_DIR  -> inspect → subset → preprocess →
                    train → explain → contextualise → ingest → alerts
    DEMO MODE     : no files                            -> the same steps on clearly-labelled
                    SYNTHETIC flows (ml/demo_data.py), so the whole application can be
                    demonstrated before the dataset is provided.

Every artefact records `data_source` so nothing synthetic can be mistaken for a
CICIoT2023 measurement.

CLI:
    python -m ml.pipeline run            # auto-detect mode, run everything, seed the store
    python -m ml.pipeline inspect        # phase 1 only
    python -m ml.pipeline status
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import pandas as pd

from backend.config import Settings, get_settings
from backend.services.alerting import generate_alerts
from backend.services.mongo import DocumentStore, get_store
from backend.utils.timeutil import utcnow
from ml.contextualiser import contextualise, load_templates
from ml.demo_data import DATA_SOURCE as DEMO_SOURCE, generate_demo_flows
from ml.explainability.profiles import build_profiles, feature_reduction_experiment, save_profiles
from ml.features import FEATURES, TARGET
from ml.preprocessing.clean import preprocess, save_splits
from ml.preprocessing.inspect import inspect_dataset, list_dataset_files, render_markdown
from ml.preprocessing.labels import classify_label
from ml.preprocessing.subset import build_subset
from ml.training.train import ModelBundle, train_models

log = logging.getLogger("pipeline")


def detect_mode(settings: Settings) -> str:
    files = list_dataset_files(Path(settings.dataset_dir)) if Path(settings.dataset_dir).exists() else []
    return "dataset" if files else "demo"


# ----------------------------------------------------------------------------- phase 1
def run_inspection(settings: Settings) -> Optional[dict]:
    if detect_mode(settings) != "dataset":
        log.warning("no CSV files under %s — inspection skipped (placeholder mode)", settings.dataset_dir)
        return None
    report = inspect_dataset(Path(settings.dataset_dir), chunksize=100_000)
    out = Path(settings.reports_dir) / "dataset_inspection.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    out.with_suffix(".md").write_text(render_markdown(report))
    return report


# ----------------------------------------------------------------------------- phases 2-4
def load_flows(settings: Settings, mode: str) -> tuple[pd.DataFrame, str, dict]:
    if mode == "dataset":
        subset_path = Path(settings.processed_dir) / "subset.parquet"
        manifest = build_subset(Path(settings.dataset_dir), subset_path, max_per_class=settings.subset_max_per_class,
                                seed=settings.random_seed)
        flows = pd.read_parquet(subset_path)
        return flows, "CICIoT2023", manifest
    flows = generate_demo_flows(n_per_class=settings.demo_flows_per_class, seed=settings.random_seed)
    return flows, DEMO_SOURCE, {"note": "synthetic demo flows; no dataset files present", "rows": len(flows)}


def train_and_explain(flows: pd.DataFrame, settings: Settings, data_source: str, manifest: dict,
                      fast: bool = False) -> dict:
    t0 = time.perf_counter()
    splits, prep = preprocess(flows, seed=settings.random_seed)
    save_splits(splits, prep, Path(settings.processed_dir))
    meta = train_models(
        splits, Path(settings.artifacts_dir), seed=settings.random_seed, data_source=data_source,
        extra_meta={"preprocess_report": prep.to_dict(), "subset_manifest": manifest},
        rf_estimators=60 if fast else 200, xgb_estimators=120 if fast else 400,
    )
    bundle = ModelBundle(Path(settings.artifacts_dir), meta["version"])
    rf = bundle.load("random_forest")
    xg = bundle.load("xgboost")
    profiles = build_profiles(
        splits["train"], splits["val"], rf, xg, bundle.label_encoder, bundle.columns, settings.random_seed,
        meta["version"], data_source, shap_sample=120 if fast else 300,
    )
    profiles["feature_reduction"] = feature_reduction_experiment(
        splits, bundle.label_encoder, profiles["global_importance"]["xgb_gain"], settings.random_seed,
        ks=(10, 20, len(bundle.columns)) if fast else (10, 15, 20, len(bundle.columns)),
    )
    save_profiles(profiles, bundle.dir)
    meta["elapsed_seconds"] = round(time.perf_counter() - t0, 2)
    return {"meta": meta, "profiles": profiles, "splits": splits, "bundle": bundle, "preprocess": prep.to_dict()}


# ----------------------------------------------------------------------------- phases 5-6
def ingest_and_alert(flows: pd.DataFrame, bundle: ModelBundle, profiles: dict, settings: Settings,
                     store: DocumentStore, data_source: str, batch_size: int = 5000) -> dict:
    templates = load_templates(Path(settings.scenarios_dir) / "scenarios.yaml")
    profiles_by_label = {p["raw_label"]: p for p in profiles["profiles"]}
    events_coll = store["security_events"]
    events_coll.delete_many({})
    store["alerts"].delete_many({})

    t0 = time.perf_counter()
    all_events: List[dict] = []
    batch: List[dict] = []
    ingested = 0

    def flush(b: List[dict]) -> None:
        nonlocal ingested
        if not b:
            return
        df = pd.DataFrame([e["features"] for e in b])
        for c in bundle.columns:
            if c not in df.columns:
                df[c] = 0.0
        pred = bundle.predict(df)
        for e, (_, p) in zip(b, pred.iterrows()):
            li, _ = classify_label(p["predicted_label"])
            e["prediction"] = {
                "label": p["predicted_label"],
                "attack_type": li.attack_type if li else p["predicted_label"],
                "category": li.category if li else "Unknown",
                "confidence": float(p["confidence"]),
                "model_version": bundle.version,
                "model": bundle.primary_name,
            }
        events_coll.insert_many(b, ordered=False)
        ingested += len(b)
        all_events.extend(b)

    provenance = "synthesized"  # entity/time context is synthesized for both modes (D2)
    for ev in contextualise(flows, templates, seed=settings.random_seed, data_source=data_source, provenance=provenance):
        batch.append(ev)
        if len(batch) >= batch_size:
            flush(batch)
            batch = []
    flush(batch)
    ingest_seconds = time.perf_counter() - t0

    alerts = generate_alerts(all_events, profiles_by_label, bundle.version)
    if alerts:
        store["alerts"].insert_many(alerts, ordered=False)

    # scenario ground truth summary (evaluation only)
    scen: Dict[str, dict] = {}
    for e in all_events:
        gt = e["ground_truth"]
        if not gt.get("scenario_id"):
            continue
        s = scen.setdefault(gt["scenario_id"], {"_id": gt["scenario_id"], "name": gt["scenario_name"], "stages": {},
                                                "event_count": 0, "sources": set(), "targets": set()})
        s["event_count"] += 1
        s["sources"].add(e["source_ip"])
        s["targets"].add(e["destination_ip"])
        st = s["stages"].setdefault(gt["stage_id"], {"stage_id": gt["stage_id"], "label": gt["label"], "index": gt["stage_index"],
                                                     "event_count": 0, "first_seen": e["timestamp"], "last_seen": e["timestamp"]})
        st["event_count"] += 1
        st["first_seen"] = min(st["first_seen"], e["timestamp"])
        st["last_seen"] = max(st["last_seen"], e["timestamp"])
    store["scenarios"].delete_many({})
    if scen:
        store["scenarios"].insert_many([
            {**s, "sources": sorted(s["sources"]), "targets": sorted(s["targets"]),
             "stages": sorted(s["stages"].values(), key=lambda x: x["index"])} for s in scen.values()
        ])

    run = {
        "_id": f"ing_{int(time.time())}",
        "created_at": utcnow(),
        "data_source": data_source,
        "provenance": provenance,
        "events_ingested": ingested,
        "alerts_generated": len(alerts),
        "scenarios": len(scen),
        "ingest_seconds": round(ingest_seconds, 2),
        "model_version": bundle.version,
        "batch_size": batch_size,
    }
    store["ingestion_runs"].insert_one(run)
    return run


def seed_store_metadata(store: DocumentStore, meta: dict, profiles: dict, inspection: Optional[dict], prep: dict) -> None:
    store["models"].delete_many({"version": meta["version"]})
    store["models"].insert_one({"_id": meta["version"], **{k: v for k, v in meta.items() if k != "_id"}})
    store["behavior_profiles"].delete_many({})
    store["behavior_profiles"].insert_many([{"_id": f"bp_{p['raw_label']}", **p} for p in profiles["profiles"]])
    store["behavior_profiles"].insert_one({"_id": "bp__global", "kind": "global",
                                           "global_importance": profiles["global_importance"],
                                           "global_top10": profiles["global_top10"],
                                           "method_agreement": profiles["method_agreement"],
                                           "feature_reduction": profiles.get("feature_reduction", []),
                                           "shap_available": profiles["shap_available"],
                                           "model_version": profiles["model_version"],
                                           "data_source": profiles["data_source"]})
    store["dataset_stats"].delete_many({})
    store["dataset_stats"].insert_one({
        "_id": "latest",
        "mode": "dataset" if inspection else "demo",
        "inspection": inspection,
        "preprocess_report": prep,
        "generated_at": utcnow(),
    })


def run_all(settings: Optional[Settings] = None, store: Optional[DocumentStore] = None, fast: bool = False) -> dict:
    settings = settings or get_settings()
    store = store or get_store()
    mode = detect_mode(settings)
    log.info("pipeline mode: %s (DATASET_DIR=%s)", mode, settings.dataset_dir)
    inspection = run_inspection(settings) if mode == "dataset" else None
    flows, data_source, manifest = load_flows(settings, mode)
    log.info("flows: %d rows, source=%s", len(flows), data_source)
    res = train_and_explain(flows, settings, data_source, manifest, fast=fast)
    seed_store_metadata(store, res["meta"], res["profiles"], inspection, res["preprocess"])
    run = ingest_and_alert(flows, res["bundle"], res["profiles"], settings, store, data_source)
    summary = {
        "mode": mode,
        "data_source": data_source,
        "model_version": res["meta"]["version"],
        "primary_model": res["meta"]["primary_model"],
        "test_macro_f1": {m: r["test"]["macro_f1"] for m, r in res["meta"]["models"].items()},
        "events": run["events_ingested"],
        "alerts": run["alerts_generated"],
        "scenarios": run["scenarios"],
        "train_seconds": res["meta"]["elapsed_seconds"],
    }
    log.info("pipeline complete: %s", summary)
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["run", "inspect", "status"])
    ap.add_argument("--fast", action="store_true", help="smaller models (demo / CI)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    if args.command == "inspect":
        r = run_inspection(settings)
        print(json.dumps(r["scope"] if r else {"mode": "demo", "note": "no dataset files"}, indent=2, default=str))
        return 0
    if args.command == "status":
        print(json.dumps({"mode": detect_mode(settings), "dataset_dir": str(settings.dataset_dir),
                          "artifacts": str(settings.artifacts_dir)}, indent=2))
        return 0
    print(json.dumps(run_all(settings, fast=args.fast), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
