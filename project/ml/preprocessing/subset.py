"""Stratified, capped experimental subset built by streaming the raw CSV files.

Per-class reservoir sampling (Algorithm R) across all chunks of all files with a fixed
seed.  Classes with fewer rows than the cap are kept in full.  The manifest records the
files, the cap, the seed and how many rows were seen/kept per class, so the subset is
reproducible and its construction is auditable.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from ml.features import FEATURES, TARGET
from ml.preprocessing.inspect import list_dataset_files, read_header, _read_chunks, scan_file_lines
from ml.preprocessing.labels import classify_label

log = logging.getLogger(__name__)


class _Reservoir:
    def __init__(self, cap: int, rng: np.random.Generator):
        self.cap = cap
        self.rng = rng
        self.seen = 0
        self.rows: List[pd.DataFrame] = []
        self._n_kept = 0

    def offer(self, frame: pd.DataFrame) -> None:
        n = len(frame)
        if n == 0:
            return
        if self._n_kept + n <= self.cap:
            self.rows.append(frame)
            self._n_kept += n
            self.seen += n
            return
        # element-wise reservoir on the overflow part
        combined = pd.concat(self.rows, ignore_index=True) if self.rows else frame.iloc[0:0]
        for i in range(n):
            self.seen += 1
            if len(combined) < self.cap:
                combined = pd.concat([combined, frame.iloc[[i]]], ignore_index=True)
            else:
                j = int(self.rng.integers(0, self.seen))
                if j < self.cap:
                    combined.iloc[j] = frame.iloc[i].to_numpy()
        self.rows = [combined]
        self._n_kept = len(combined)

    def frame(self) -> pd.DataFrame:
        return pd.concat(self.rows, ignore_index=True) if self.rows else pd.DataFrame()


def build_subset(data_dir: Path, out_path: Path, max_per_class: int = 100_000, seed: int = 42,
                 chunksize: int = 100_000, max_files: Optional[int] = None) -> dict:
    files = list_dataset_files(Path(data_dir))
    if max_files:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(f"no CSV files in {data_dir}")
    rng = np.random.default_rng(seed)
    reservoirs: Dict[str, _Reservoir] = {}
    seen: Dict[str, int] = {}
    dropped_out_of_scope = 0
    for idx, f in enumerate(files, 1):
        header = read_header(f)
        scan = scan_file_lines(f, len(header))
        log.info("[%d/%d] %s", idx, len(files), f.name)
        for chunk in _read_chunks(f, len(header), chunksize, strict=scan["malformed_lines"] > 0):
            chunk[TARGET] = chunk[TARGET].astype(str).str.strip()
            keep_cols = [c for c in FEATURES if c in chunk.columns] + [TARGET]
            for lbl, part in chunk.groupby(TARGET, sort=False):
                li, _ = classify_label(lbl)
                if li is None or not li.in_scope:
                    dropped_out_of_scope += len(part)
                    continue
                seen[lbl] = seen.get(lbl, 0) + len(part)
                res = reservoirs.setdefault(lbl, _Reservoir(max_per_class, rng))
                res.offer(part[keep_cols])
    frames = [r.frame() for r in reservoirs.values()]
    subset = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    subset.to_parquet(out_path, index=False)
    manifest = {
        "files": [str(f) for f in files],
        "max_per_class": max_per_class,
        "seed": seed,
        "rows_seen_in_scope": seen,
        "rows_kept": subset[TARGET].value_counts().to_dict(),
        "rows_dropped_out_of_scope": dropped_out_of_scope,
        "total_rows": len(subset),
        "output": str(out_path),
    }
    out_path.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest
