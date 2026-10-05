"""
evaluate.py
Score predicted hallucination flags against RAGTruth's ground-truth `is_hallucinated` labels.

Requires: pip install scikit-learn
"""
from typing import List


def score(y_true: List[bool], y_pred: List[bool]) -> dict:
    from sklearn.metrics import (
        precision_recall_fscore_support,
        balanced_accuracy_score,
        accuracy_score,
        confusion_matrix,
    )

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=[False, True]).tolist()
    return {
        "n": len(y_true),
        "positive_rate_true": sum(y_true) / len(y_true) if y_true else 0.0,
        "positive_rate_pred": sum(y_pred) / len(y_pred) if y_pred else 0.0,
        "accuracy": accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
    }


def print_report(metrics: dict, name: str = "model") -> None:
    print(f"\n=== {name} (n={metrics['n']}) ===")
    print(f"Base rate (ground truth hallucinated): {metrics['positive_rate_true']:.1%}")
    print(f"Predicted hallucinated rate:            {metrics['positive_rate_pred']:.1%}")
    print(f"Accuracy:          {metrics['accuracy']:.3f}")
    print(f"Balanced accuracy: {metrics['balanced_accuracy']:.3f}")
    print(f"Precision:         {metrics['precision']:.3f}")
    print(f"Recall:            {metrics['recall']:.3f}")
    print(f"F1:                {metrics['f1']:.3f}")
    (tn, fp), (fn, tp) = metrics["confusion_matrix"]
    print(f"Confusion matrix:  TN={tn}  FP={fp}  FN={fn}  TP={tp}")


if __name__ == "__main__":
    # Sanity check with a known confusion matrix, no model or dataset needed.
    y_true = [True, True, True, False, False, False, False, False]
    y_pred = [True, True, False, False, False, True, False, False]
    m = score(y_true, y_pred)
    print_report(m, name="dummy_check")
    assert m["confusion_matrix"] == [[4, 1], [1, 2]], m["confusion_matrix"]
    print("\nassertion passed: confusion matrix matches hand-computed TN/FP/FN/TP")
