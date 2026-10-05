"""Scenario Contextualiser (architecture review §2.3, decision D2).

Attaches reproducible *synthesized* entity and time context to real flow records so
that a knowledge graph can be built, while leaving feature values and labels untouched.

Every produced event carries:
    context.provenance = "synthesized"   (or "dataset" when the source has IPs/timestamps)
    ground_truth = {label, scenario_id, stage_id, scenario_name}  -> hidden from agents

Events are written as MongoDB documents in the shape defined in the architecture
review §5.1.  The dataset label is stored ONLY in ground_truth; the `prediction`
sub-document is filled by the model during ingestion (ml/pipeline.py).
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import numpy as np
import pandas as pd
import yaml

from backend.utils.ids import new_id
from ml.features import FEATURES, TARGET

log = logging.getLogger(__name__)

GENERATOR_VERSION = "1.0"


def _protocol_of(row: Dict[str, float]) -> str:
    """Derive a coarse protocol string from the dataset's own indicator columns."""
    for name in ("HTTP", "HTTPS", "DNS", "SSH", "Telnet", "SMTP", "IRC", "DHCP"):
        if row.get(name, 0) > 0.5:
            return name
    if row.get("ARP", 0) > 0.5:
        return "ARP"
    if row.get("ICMP", 0) > 0.5:
        return "ICMP"
    if row.get("TCP", 0) > 0.5:
        return "TCP"
    if row.get("UDP", 0) > 0.5:
        return "UDP"
    pt = row.get("Protocol Type", 0)
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(int(pt) if pt == pt else -1, "OTHER")


class FlowPool:
    """Draws flows of a given label without replacement (falls back to reuse when exhausted)."""

    def __init__(self, flows: pd.DataFrame, seed: int):
        self.rng = np.random.default_rng(seed)
        self.groups: Dict[str, pd.DataFrame] = {
            lbl: part.sample(frac=1.0, random_state=seed).reset_index(drop=True)
            for lbl, part in flows.groupby(TARGET)
        }
        self.cursor: Dict[str, int] = {lbl: 0 for lbl in self.groups}
        self.reused: Dict[str, int] = {}

    def available_labels(self) -> List[str]:
        return list(self.groups)

    def draw(self, label: str, n: int) -> pd.DataFrame:
        if label not in self.groups:
            raise KeyError(f"no flows available for label {label}")
        g = self.groups[label]
        start = self.cursor[label]
        if start + n <= len(g):
            self.cursor[label] = start + n
            return g.iloc[start:start + n]
        # wrap around (reuse) — recorded so the manifest is honest about it
        self.reused[label] = self.reused.get(label, 0) + (start + n - len(g))
        first = g.iloc[start:]
        rest = g.sample(n=n - len(first), replace=len(g) < n - len(first), random_state=int(self.rng.integers(1 << 31)))
        self.cursor[label] = 0
        return pd.concat([first, rest])


def load_templates(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def contextualise(flows: pd.DataFrame, templates: dict, seed: int = 42, base_time: Optional[datetime] = None,
                  data_source: str = "CICIoT2023", provenance: str = "synthesized",
                  scenario_repeats: int = 1) -> Iterator[Dict]:
    """Yield event documents. `flows` has the 46 features + `label`."""
    rng = random.Random(seed)
    pool = FlowPool(flows, seed)
    devices = templates["devices"]
    # attacker pool: the preferred addresses from the template first, then the rest of the RFC 5737
    # documentation ranges, shuffled with the seed. Each scenario draws fresh addresses so that
    # scenarios do not bleed into each other (except when a template explicitly reuses one).
    attackers = list(templates["attackers"])
    extra = [f"203.0.113.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)]
    extra = [a for a in extra if a not in attackers]
    rng.shuffle(extra)
    attacker_pool = attackers + extra
    pool_cursor = 0
    base_time = base_time or (datetime.now(timezone.utc) - timedelta(hours=6))
    available = set(pool.available_labels())

    t_cursor = base_time
    scenario_specs = templates["scenarios"] * max(1, scenario_repeats)
    for s_idx, spec in enumerate(scenario_specs):
        needed = [st["label"] for st in spec["stages"]]
        if any(lbl not in available for lbl in needed):
            log.warning("skipping scenario %s: missing labels %s", spec["name"], [l for l in needed if l not in available])
            continue
        scenario_id = new_id("scn")
        n_sources = int(spec.get("sources", 1))
        sources = attacker_pool[pool_cursor:pool_cursor + n_sources]
        pool_cursor += n_sources
        if len(sources) < n_sources:  # pool exhausted -> wrap (recorded in log)
            pool_cursor = 0
            sources = attacker_pool[:n_sources]
            log.warning("attacker pool exhausted; reusing addresses from the start of the pool")
        primary_targets = rng.sample(devices, k=min(max(st["targets"] for st in spec["stages"]), len(devices)))
        t_stage = t_cursor + timedelta(seconds=rng.randint(0, 900))
        prev_end = t_stage
        for st_idx, st in enumerate(spec["stages"]):
            stage_id = f"stg_{st_idx + 1}"
            start = prev_end + timedelta(seconds=st.get("gap_seconds", 0))
            spread = max(int(st.get("spread_seconds", 60)), 1)
            targets = primary_targets[: st["targets"]]
            drawn = pool.draw(st["label"], int(st["flows"]))
            offsets = sorted(rng.uniform(0, spread) for _ in range(len(drawn)))
            for (_, row), off in zip(drawn.iterrows(), offsets):
                feats = {f: float(row[f]) for f in FEATURES if f in row.index}
                src = rng.choice(sources)
                dev = rng.choice(targets)
                ts = start + timedelta(seconds=off)
                yield {
                    "_id": new_id("evt"),
                    "timestamp": ts,
                    "source_ip": src,
                    "destination_ip": dev["ip"],
                    "device_id": dev["device_id"],
                    "device_type": dev["device_type"],
                    "protocol": _protocol_of(feats),
                    "log_source": data_source,
                    "features": feats,
                    "prediction": None,
                    "context": {"provenance": provenance, "generator_version": GENERATOR_VERSION, "seed": seed,
                                "scenario_name": spec["name"]},
                    "dataset": {"source": data_source},
                    "ground_truth": {"label": st["label"], "scenario_id": scenario_id, "stage_id": stage_id,
                                     "scenario_name": spec["name"], "stage_index": st_idx + 1,
                                     "stage_count": len(spec["stages"])},
                }
            prev_end = start + timedelta(seconds=spread)
        t_cursor = t_cursor + timedelta(seconds=rng.randint(600, 1500))

    # background benign traffic between devices (and a little device->internet-like traffic)
    bg = templates.get("background", {})
    n_benign = int(bg.get("benign_flows", 0))
    if n_benign and "BenignTraffic" in available:
        drawn = pool.draw("BenignTraffic", n_benign)
        spread = int(bg.get("spread_seconds", 3600))
        for _, row in drawn.iterrows():
            feats = {f: float(row[f]) for f in FEATURES if f in row.index}
            a, b = rng.sample(devices, 2)
            ts = base_time + timedelta(seconds=rng.uniform(0, spread))
            yield {
                "_id": new_id("evt"),
                "timestamp": ts,
                "source_ip": a["ip"],
                "destination_ip": b["ip"],
                "device_id": b["device_id"],
                "device_type": b["device_type"],
                "protocol": _protocol_of(feats),
                "log_source": data_source,
                "features": feats,
                "prediction": None,
                "context": {"provenance": provenance, "generator_version": GENERATOR_VERSION, "seed": seed,
                            "scenario_name": "background"},
                "dataset": {"source": data_source},
                "ground_truth": {"label": "BenignTraffic", "scenario_id": None, "stage_id": None,
                                 "scenario_name": "background", "stage_index": None, "stage_count": None},
            }
    log.info("contextualiser reuse counts: %s", pool.reused)
