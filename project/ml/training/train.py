"""Phase 3 — Random Forest and XGBoost training with a model registry.

Both models are trained on the same splits with class-balanced weights.  Macro-F1 on
the validation split selects the *primary* model used for alert generation.  All
artefacts (models, label encoder, medians, metrics, model card) are versioned under
``ARTIFACTS_DIR/<version>/``.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

from ml.evaluation.metrics import evaluate_predictions
from ml.features import FEATURES, TARGET

log = logging.getLogger(__name__)


@dataclass
class TrainedModel:
    name: str
    estimator: object
    train_seconds: float
    params: dict


def _feature_cols(df: pd.DataFrame) -> List[str]:
    return [c for c in FEATURES if c in df.columns]


def train_random_forest(X, y, seed: int, n_estimators: int = 200, max_depth: Optional[int] = None) -> TrainedModel:
    t0 = time.perf_counter()
    rf = RandomForestClassifier(
        n_estimators=n_estimators, max_depth=max_depth, class_weight="balanced_subsample",
        n_jobs=-1, random_state=seed, min_samples_leaf=1,
    )
    rf.fit(X, y)
    return TrainedModel("random_forest", rf, time.perf_counter() - t0, rf.get_params())


def train_xgboost(X, y, X_val, y_val, seed: int, n_classes: int, max_depth: int = 8, eta: float = 0.1,
                  n_estimators: int = 400) -> TrainedModel:
    import xgboost as xgb

    t0 = time.perf_counter()
    sw = compute_sample_weight("balanced", y)
    clf = xgb.XGBClassifier(
        objective="multi:softprob", num_class=n_classes, tree_method="hist", max_depth=max_depth,
        learning_rate=eta, n_estimators=n_estimators, subsample=0.9, colsample_bytree=0.9,
        random_state=seed, n_jobs=2, early_stopping_rounds=30, eval_metric="mlogloss",
    )
    clf.fit(X, y, sample_weight=sw, eval_set=[(X_val, y_val)], verbose=False)
    params = clf.get_params()
    params["best_iteration"] = int(getattr(clf, "best_iteration", n_estimators))
    return TrainedModel("xgboost", clf, time.perf_counter() - t0, params)


def train_models(splits: Dict[str, pd.DataFrame], artifacts_dir: Path, seed: int = 42,
                 data_source: str = "unknown", extra_meta: Optional[dict] = None,
                 rf_estimators: int = 200, xgb_estimators: int = 400) -> dict:
    cols = _feature_cols(splits["train"])
    le = LabelEncoder().fit(splits["train"][TARGET])
    classes = list(le.classes_)
    Xtr, ytr = splits["train"][cols].to_numpy(np.float32), le.transform(splits["train"][TARGET])
    Xva, yva = splits["val"][cols].to_numpy(np.float32), le.transform(splits["val"][TARGET])
    Xte, yte = splits["test"][cols].to_numpy(np.float32), le.transform(splits["test"][TARGET])

    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = artifacts_dir / version
    out.mkdir(parents=True, exist_ok=True)

    log.info("training RandomForest on %d rows x %d features", len(Xtr), len(cols))
    rf = train_random_forest(Xtr, ytr, seed, n_estimators=rf_estimators)
    log.info("training XGBoost")
    xg = train_xgboost(Xtr, ytr, Xva, yva, seed, len(classes), n_estimators=xgb_estimators)

    results = {}
    for tm in (rf, xg):
        t0 = time.perf_counter()
        pred_te = tm.estimator.predict(Xte)
        infer_s = time.perf_counter() - t0
        pred_va = tm.estimator.predict(Xva)
        m_test = evaluate_predictions(yte, pred_te, classes)
        m_val = evaluate_predictions(yva, pred_va, classes)
        results[tm.name] = {
            "train_seconds": round(tm.train_seconds, 3),
            "inference_seconds_test": round(infer_s, 4),
            "inference_us_per_row": round(infer_s / max(len(Xte), 1) * 1e6, 2),
            "validation": m_val,
            "test": m_test,
            "params": {k: (v if isinstance(v, (int, float, str, bool, type(None))) else str(v)) for k, v in tm.params.items()},
        }
        joblib.dump(tm.estimator, out / f"{tm.name}.joblib")

    primary = max(results, key=lambda k: results[k]["validation"]["macro_f1"])
    joblib.dump(le, out / "label_encoder.joblib")
    meta = {
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data_source": data_source,
        "feature_columns": cols,
        "classes": classes,
        "n_train": int(len(Xtr)), "n_val": int(len(Xva)), "n_test": int(len(Xte)),
        "seed": seed,
        "primary_model": primary,
        "selection_rule": "highest validation macro-F1",
        "models": results,
        **(extra_meta or {}),
    }
    (out / "model_card.json").write_text(json.dumps(meta, indent=2, default=str))
    (artifacts_dir / "LATEST").write_text(version)
    log.info("models saved to %s (primary=%s)", out, primary)
    return meta


class ModelBundle:
    """Loads a trained version for inference (used by alert generation and the API)."""

    def __init__(self, artifacts_dir: Path, version: Optional[str] = None):
        artifacts_dir = Path(artifacts_dir)
        if version is None:
            version = (artifacts_dir / "LATEST").read_text().strip()
        self.dir = artifacts_dir / version
        self.meta = json.loads((self.dir / "model_card.json").read_text())
        self.version = version
        self.label_encoder = joblib.load(self.dir / "label_encoder.joblib")
        self.primary_name = self.meta["primary_model"]
        self.estimator = joblib.load(self.dir / f"{self.primary_name}.joblib")
        self.columns = self.meta["feature_columns"]

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        X = df[self.columns].to_numpy(np.float32)
        proba = self.estimator.predict_proba(X)
        idx = proba.argmax(axis=1)
        return pd.DataFrame({
            "predicted_label": self.label_encoder.inverse_transform(idx),
            "confidence": proba.max(axis=1).astype(float),
        }, index=df.index)

    def load(self, name: str):
        return joblib.load(self.dir / f"{name}.joblib")
