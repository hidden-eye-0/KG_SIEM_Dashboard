"""
Run this SECOND, after run_baseline.py works. Needs an Anthropic API key (for claim
decomposition) AND will download the NLI model (~370MB) on first run.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python scripts/run_pipeline_eval.py                    # bundled 120-example sample
    python scripts/run_pipeline_eval.py --n 20              # quick smoke test
    python scripts/run_pipeline_eval.py --threshold 0.6     # tune the contradiction threshold
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data_loader import load_sample, load_ragtruth_list  # noqa: E402
from src.pipeline import HallucinationPipeline  # noqa: E402
from src.evaluate import score, print_report  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="path to full response.jsonl (default: use bundled sample)")
    ap.add_argument("--source", help="path to full source_info.jsonl")
    ap.add_argument("--n", type=int, default=None)
    ap.add_argument("--threshold", type=float, default=0.5,
                     help="contradiction probability above which a claim flags the response")
    ap.add_argument("--decompose_model", default="gemini-3.6-flash")
    args = ap.parse_args()

    if args.data and args.source:
        examples = load_ragtruth_list(args.data, args.source, split="test")
    else:
        examples = load_sample(str(Path(__file__).resolve().parent.parent / "data" / "sample_ragtruth.jsonl"))

    if args.n:
        examples = examples[: args.n]

    pipeline = HallucinationPipeline(
        decompose_model=args.decompose_model,
        contradiction_threshold=args.threshold,
    )

    print(f"Running claim+NLI pipeline over {len(examples)} examples "
          f"(threshold={args.threshold})...")
    results = pipeline.run_over(examples)

    y_true = [ex.is_hallucinated for ex in examples]
    y_pred = [r.predicted_hallucinated for r in results]
    metrics = score(y_true, y_pred)
    print_report(metrics, name=f"claim_nli_pipeline (threshold={args.threshold})")

    # Show a few disagreements so you can eyeball what the model is getting wrong --
    # useful for your Review report's "error analysis" section.
    print("\n--- sample disagreements (first 3) ---")
    shown = 0
    for ex, r in zip(examples, results):
        if ex.is_hallucinated != r.predicted_hallucinated and shown < 3:
            print(f"\nresponse_id={ex.response_id}  true={ex.is_hallucinated}  "
                  f"pred={r.predicted_hallucinated}  task={ex.task_type}")
            for c, v in zip(r.claims, r.verifications):
                print(f"    [{v.label:12s} c={v.scores['contradiction']:.2f}] {c}")
            shown += 1


if __name__ == "__main__":
    main()
