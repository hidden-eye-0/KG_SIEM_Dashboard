"""Phase 4 — feature importance comparison, SHAP, and attack-specific behavioural profiles.

For every class the following are computed *from the trained models and data*:

* Random Forest impurity importance (global)
* Random Forest permutation importance (validation split, global)
* XGBoost gain importance (global)
* SHAP mean |value| per class (TreeExplainer on XGBoost, stratified sample per class)
* class-vs-benign feature statistics with z-scores

A behavioural profile = consensus top-k features (rank aggregation across methods,
class-specific SHAP and z-scores weighted highest), protocol-indicator rates, feature
group summary and a template-generated statement that uses the mandated phrasing:
"...provide behavioral evidence associated with the labelled <class> class".
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

from ml.features import FEATURE_GROUPS, FEATURES, PROTOCOL_INDICATORS, TARGET, group_of
from ml.preprocessing.labels import classify_label

log = logging.getLogger(__name__)

PROFILE_PHRASE = "provide behavioral evidence associated with the labelled {name} class"


def _rank_scores(values: Dict[str, float]) -> Dict[str, float]:
    """Convert importance values to normalised rank scores in [0,1] (1 = most important)."""
    items = sorted(values.items(), key=lambda kv: -abs(kv[1]))
    n = len(items)
    return {k: 1.0 - i / max(n - 1, 1) for i, (k, _) in enumerate(items)}


def _rbo(a: List[str], b: List[str], p: float = 0.9) -> float:
    """Rank-biased overlap (agreement between two ranked lists)."""
    depth = max(len(a), len(b))
    if depth == 0:
        return 1.0
    score, sa, sb = 0.0, set(), set()
    for d in range(1, depth + 1):
        if d <= len(a):
            sa.add(a[d - 1])
        if d <= len(b):
            sb.add(b[d - 1])
        score += (p ** (d - 1)) * len(sa & sb) / d
    return (1 - p) * score


def compute_global_importances(rf, xgb_model, X_val: np.ndarray, y_val: np.ndarray, cols: List[str], seed: int,
                               perm_repeats: int = 3, perm_sample: int = 4000) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    out["rf_impurity"] = dict(zip(cols, map(float, rf.feature_importances_)))
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(X_val), size=min(perm_sample, len(X_val)), replace=False)
    pi = permutation_importance(rf, X_val[idx], y_val[idx], n_repeats=perm_repeats, random_state=seed, n_jobs=1, scoring="f1_macro")
    out["rf_permutation"] = dict(zip(cols, map(float, pi.importances_mean)))
    booster = xgb_model.get_booster()
    gain = booster.get_score(importance_type="gain")
    # xgboost names features f0..fn unless feature names were provided
    mapped = {}
    for k, v in gain.items():
        if k.startswith("f") and k[1:].isdigit():
            mapped[cols[int(k[1:])]] = float(v)
        else:
            mapped[k] = float(v)
    out["xgb_gain"] = {c: mapped.get(c, 0.0) for c in cols}
    return out


def compute_shap_per_class(xgb_model, X: np.ndarray, y: np.ndarray, classes: List[str], cols: List[str], seed: int,
                           per_class_sample: int = 300) -> Dict[str, Dict[str, float]]:
    """Mean |SHAP| per feature for each class using the class's own samples."""
    try:
        import shap
    except Exception as exc:  # pragma: no cover
        log.warning("shap unavailable: %s", exc)
        return {}
    rng = np.random.default_rng(seed)
    explainer = shap.TreeExplainer(xgb_model)
    result: Dict[str, Dict[str, float]] = {}
    for ci, cname in enumerate(classes):
        rows = np.flatnonzero(y == ci)
        if rows.size == 0:
            continue
        pick = rng.choice(rows, size=min(per_class_sample, rows.size), replace=False)
        sv = explainer.shap_values(X[pick])
        # shap returns list (per class) for older versions or ndarray (n, features, classes) for newer
        if isinstance(sv, list):
            mat = sv[ci]
        elif sv.ndim == 3:
            mat = sv[:, :, ci]
        else:
            mat = sv
        mean_abs = np.abs(mat).mean(axis=0)
        result[cname] = dict(zip(cols, map(float, mean_abs)))
    return result


def class_vs_benign_stats(df: pd.DataFrame, cols: List[str], benign_label: str = "BenignTraffic") -> Dict[str, Dict[str, dict]]:
    benign = df[df[TARGET] == benign_label]
    b_mean = benign[cols].mean()
    b_std = benign[cols].std().replace(0, np.nan)
    out: Dict[str, Dict[str, dict]] = {}
    for cname, part in df.groupby(TARGET):
        c_mean = part[cols].mean()
        c_std = part[cols].std()
        z = ((c_mean - b_mean) / b_std).fillna(0.0)
        out[cname] = {
            c: {"class_mean": float(c_mean[c]), "class_std": float(c_std[c]) if not np.isnan(c_std[c]) else 0.0,
                "benign_mean": float(b_mean[c]), "benign_std": float(b_std[c]) if not np.isnan(b_std[c]) else 0.0,
                "z": float(np.clip(z[c], -50, 50))}
            for c in cols
        }
    return out


def build_profiles(df_train: pd.DataFrame, df_val: pd.DataFrame, rf, xgb_model, label_encoder, cols: List[str],
                   seed: int, model_version: str, data_source: str, top_k: int = 8,
                   shap_sample: int = 300) -> dict:
    classes = list(label_encoder.classes_)
    Xva = df_val[cols].to_numpy(np.float32)
    yva = label_encoder.transform(df_val[TARGET])
    log.info("computing global importances")
    glob = compute_global_importances(rf, xgb_model, Xva, yva, cols, seed)
    log.info("computing SHAP per class")
    shap_pc = compute_shap_per_class(xgb_model, Xva, yva, classes, cols, seed, per_class_sample=shap_sample)
    stats = class_vs_benign_stats(pd.concat([df_train, df_val]), cols)

    glob_ranks = {m: _rank_scores(v) for m, v in glob.items()}
    top10 = {m: [k for k, _ in sorted(v.items(), key=lambda kv: -abs(kv[1]))[:10]] for m, v in glob.items()}
    agreement = {
        "rf_impurity_vs_xgb_gain_rbo10": _rbo(top10["rf_impurity"], top10["xgb_gain"]),
        "rf_impurity_vs_rf_permutation_rbo10": _rbo(top10["rf_impurity"], top10["rf_permutation"]),
        "rf_permutation_vs_xgb_gain_rbo10": _rbo(top10["rf_permutation"], top10["xgb_gain"]),
    }

    profiles = []
    for cname in classes:
        li, _ = classify_label(cname)
        z = {c: stats[cname][c]["z"] for c in cols}
        z_rank = _rank_scores({c: abs(v) for c, v in z.items()})
        shap_rank = _rank_scores(shap_pc[cname]) if cname in shap_pc else {c: 0.0 for c in cols}
        # consensus: class-specific evidence (SHAP, z) weighted 2x, global importances 1x each
        consensus = {
            c: 2.0 * shap_rank.get(c, 0.0) + 2.0 * z_rank[c] + glob_ranks["rf_impurity"][c]
            + glob_ranks["rf_permutation"][c] + glob_ranks["xgb_gain"][c]
            for c in cols
        }
        top = [k for k, _ in sorted(consensus.items(), key=lambda kv: -kv[1])[:top_k]]
        proto = {p: float(stats[cname][p]["class_mean"]) for p in PROTOCOL_INDICATORS if p in stats[cname]}
        dominant_proto = [p for p, r in sorted(proto.items(), key=lambda kv: -kv[1]) if r >= 0.5][:3]
        groups = {g: round(float(np.mean([consensus[c] for c in fs if c in consensus])), 3) for g, fs in FEATURE_GROUPS.items()}
        top_desc = ", ".join(
            f"{f} ({'high' if z[f] > 0 else 'low'} vs benign, z={z[f]:+.1f})" for f in top[:5]
        )
        name = li.attack_type if li else cname
        statement = (
            f"The feature combination {top_desc}"
            + (f" together with the {'/'.join(dominant_proto)} protocol indicator(s)" if dominant_proto else "")
            + f" {PROFILE_PHRASE.format(name=name)}. "
            "These are network-flow characteristics, not direct forensic evidence of the underlying actions."
        ) if cname != "BenignTraffic" else (
            "Reference profile of the labelled benign class used as the comparison baseline for z-scores."
        )
        profiles.append({
            "raw_label": cname,
            "attack_type": name,
            "category": li.category if li else "Unknown",
            "model_version": model_version,
            "data_source": data_source,
            "n_samples_train": int((df_train[TARGET] == cname).sum()),
            "top_features": top,
            "consensus_scores": {k: round(v, 4) for k, v in sorted(consensus.items(), key=lambda kv: -kv[1])[:20]},
            "importance": {
                "rf_impurity": {k: round(glob["rf_impurity"][k], 6) for k in top},
                "rf_permutation": {k: round(glob["rf_permutation"][k], 6) for k in top},
                "xgb_gain": {k: round(glob["xgb_gain"][k], 4) for k in top},
                "shap_mean_abs": {k: round(shap_pc.get(cname, {}).get(k, 0.0), 6) for k in top},
            },
            "feature_stats": {k: stats[cname][k] for k in top},
            "protocol_indicators": proto,
            "dominant_protocols": dominant_proto,
            "feature_group_scores": groups,
            "profile_statement": statement,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    return {
        "model_version": model_version,
        "data_source": data_source,
        "global_importance": {m: dict(sorted(v.items(), key=lambda kv: -abs(kv[1]))) for m, v in glob.items()},
        "global_top10": top10,
        "method_agreement": agreement,
        "shap_available": bool(shap_pc),
        "profiles": profiles,
    }


def feature_reduction_experiment(splits: Dict[str, pd.DataFrame], label_encoder, global_importance: Dict[str, float],
                                 seed: int, ks=(10, 15, 20, 46)) -> List[dict]:
    """Retrain a light RF on the top-k global features and report macro-F1 (profile quality)."""
    from sklearn.ensemble import RandomForestClassifier
    from ml.evaluation.metrics import evaluate_predictions

    ranked = [k for k, _ in sorted(global_importance.items(), key=lambda kv: -abs(kv[1]))]
    ytr = label_encoder.transform(splits["train"][TARGET])
    yte = label_encoder.transform(splits["test"][TARGET])
    rows = []
    for k in ks:
        cols = ranked[:k]
        rf = RandomForestClassifier(n_estimators=60, class_weight="balanced_subsample", n_jobs=-1, random_state=seed)
        rf.fit(splits["train"][cols].to_numpy(np.float32), ytr)
        m = evaluate_predictions(yte, rf.predict(splits["test"][cols].to_numpy(np.float32)), list(label_encoder.classes_))
        rows.append({"k": k, "macro_f1": m["macro_f1"], "accuracy": m["accuracy"], "features": cols})
    return rows


def save_profiles(bundle: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "behavior_profiles.json"
    p.write_text(json.dumps(bundle, indent=2, default=str))
    return p
