"""Detection metrics (accuracy, precision, recall, F1, per-class table, confusion matrix)."""
from __future__ import annotations

from typing import List

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)


def evaluate_predictions(y_true, y_pred, classes: List[str]) -> dict:
    labels = list(range(len(classes)))
    acc = accuracy_score(y_true, y_pred)
    p_mac, r_mac, f_mac, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    p_w, r_w, f_w, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, average="weighted", zero_division=0)
    p_c, r_c, f_c, s_c = precision_recall_fscore_support(y_true, y_pred, labels=labels, average=None, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    per_class = [
        {"class": classes[i], "precision": float(p_c[i]), "recall": float(r_c[i]), "f1": float(f_c[i]), "support": int(s_c[i])}
        for i in labels
    ]
    return {
        "accuracy": float(acc),
        "macro_precision": float(p_mac), "macro_recall": float(r_mac), "macro_f1": float(f_mac),
        "weighted_precision": float(p_w), "weighted_recall": float(r_w), "weighted_f1": float(f_w),
        "per_class": per_class,
        "confusion_matrix": {"labels": classes, "matrix": cm.astype(int).tolist()},
        "n_samples": int(len(y_true)),
    }
