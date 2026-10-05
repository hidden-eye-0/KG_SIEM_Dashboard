"""Phase 2 — preprocessing pipeline (cleaning, normalisation, splitting).

Design (from the architecture review §9.3/9.4):
* strip column names, keep the 46 expected features (missing ones are reported, not invented)
* `inf -> NaN`, then median imputation fitted on the TRAINING split only (no leakage)
* exact duplicate rows are dropped (count reported)
* float32 for all features
* stratified 70 / 15 / 15 split with a fixed seed
* label mapping to (attack_type, category) with Mirai / out-of-scope labels removed
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.features import FEATURES, TARGET
from ml.preprocessing.labels import classify_label


@dataclass
class PreprocessReport:
    input_rows: int = 0
    rows_after_scope_filter: int = 0
    rows_after_dedupe: int = 0
    duplicates_dropped: int = 0
    excluded_label_rows: Dict[str, int] = field(default_factory=dict)
    unknown_label_rows: int = 0
    inf_cells_replaced: int = 0
    nan_cells_imputed: int = 0
    missing_feature_columns: List[str] = field(default_factory=list)
    medians: Dict[str, float] = field(default_factory=dict)
    class_counts: Dict[str, int] = field(default_factory=dict)
    split_sizes: Dict[str, int] = field(default_factory=dict)
    split_strategy: str = "stratified 70/15/15"
    seed: int = 42

    def to_dict(self) -> dict:
        return self.__dict__


def map_labels(df: pd.DataFrame, report: PreprocessReport) -> pd.DataFrame:
    """Attach attack_type/category and drop out-of-scope rows."""
    raw = df[TARGET].astype(str).str.strip()
    keep = np.ones(len(df), dtype=bool)
    attack_type = np.empty(len(df), dtype=object)
    category = np.empty(len(df), dtype=object)
    for lbl in raw.unique():
        li, _ = classify_label(lbl)
        mask = (raw == lbl).to_numpy()
        if li is None:
            report.unknown_label_rows += int(mask.sum())
            keep &= ~mask
            continue
        if not li.in_scope:
            report.excluded_label_rows[lbl] = int(mask.sum())
            keep &= ~mask
            continue
        attack_type[mask] = li.attack_type
        category[mask] = li.category
    out = df.loc[keep].copy()
    out["attack_type"] = attack_type[keep]
    out["category"] = category[keep]
    out[TARGET] = raw[keep].to_numpy()
    return out


def clean_features(df: pd.DataFrame, report: PreprocessReport) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    present = [c for c in FEATURES if c in df.columns]
    report.missing_feature_columns = [c for c in FEATURES if c not in df.columns]
    for c in present:
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors="coerce")
    X = df[present].astype(np.float32)
    inf_mask = ~np.isfinite(X.to_numpy()) & ~np.isnan(X.to_numpy())
    report.inf_cells_replaced = int(inf_mask.sum())
    X = X.replace([np.inf, -np.inf], np.nan)
    df[present] = X
    return df


def dedupe(df: pd.DataFrame, report: PreprocessReport) -> pd.DataFrame:
    cols = [c for c in FEATURES if c in df.columns] + [TARGET]
    before = len(df)
    out = df.drop_duplicates(subset=cols)
    report.duplicates_dropped = before - len(out)
    return out


def split(df: pd.DataFrame, seed: int, report: PreprocessReport,
          test_size: float = 0.15, val_size: float = 0.15) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    strat = df[TARGET]
    # guard: stratification needs >= 2 members per class in each split
    counts = strat.value_counts()
    tiny = counts[counts < 7].index.tolist()
    if tiny:
        report.split_strategy += f" (classes with <7 rows not stratified: {tiny})"
        strat = strat.where(~strat.isin(tiny), "__tiny__")
    train, rest = train_test_split(df, test_size=test_size + val_size, random_state=seed, stratify=strat)
    rest_strat = strat.loc[rest.index]
    rel = test_size / (test_size + val_size)
    val, test = train_test_split(rest, test_size=rel, random_state=seed, stratify=rest_strat)
    report.split_sizes = {"train": len(train), "val": len(val), "test": len(test)}
    return train, val, test


def fit_imputer(train: pd.DataFrame, report: PreprocessReport) -> Dict[str, float]:
    present = [c for c in FEATURES if c in train.columns]
    med = train[present].median(numeric_only=True)
    med = med.fillna(0.0)
    report.medians = {c: float(med[c]) for c in present}
    return report.medians


def apply_imputer(df: pd.DataFrame, medians: Dict[str, float], report: Optional[PreprocessReport] = None) -> pd.DataFrame:
    df = df.copy()
    cols = [c for c in medians if c in df.columns]
    nan_count = int(df[cols].isna().to_numpy().sum())
    if report is not None:
        report.nan_cells_imputed += nan_count
    df[cols] = df[cols].fillna(value={c: medians[c] for c in cols})
    return df


def preprocess(df: pd.DataFrame, seed: int = 42) -> Tuple[Dict[str, pd.DataFrame], PreprocessReport]:
    """Full pipeline on an in-memory frame (the subset / demo frame)."""
    rep = PreprocessReport(seed=seed, input_rows=len(df))
    df = clean_features(df, rep)
    df = map_labels(df, rep)
    rep.rows_after_scope_filter = len(df)
    df = dedupe(df, rep)
    rep.rows_after_dedupe = len(df)
    rep.class_counts = df[TARGET].value_counts().to_dict()
    train, val, test = split(df, seed, rep)
    med = fit_imputer(train, rep)
    train = apply_imputer(train, med, rep)
    val = apply_imputer(val, med, rep)
    test = apply_imputer(test, med, rep)
    return {"train": train, "val": val, "test": test}, rep


def save_splits(splits: Dict[str, pd.DataFrame], rep: PreprocessReport, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, frame in splits.items():
        frame.to_parquet(out_dir / f"{name}.parquet", index=False)
    (out_dir / "preprocess_report.json").write_text(json.dumps(rep.to_dict(), indent=2, default=str))
