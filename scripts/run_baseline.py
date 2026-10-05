"""
Run this FIRST. It needs only an Anthropic API key -- no model download.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python scripts/run_baseline.py                       # uses bundled 120-example sample
    python scripts/run_baseline.py --n 30                 # quick smoke test, first 30 only
    python scripts/run_baseline.py --data /path/to/full/response.jsonl \
                                    --source /path/to/full/source_info.jsonl
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data_loader import load_sample, load_ragtruth_list  # noqa: E402
from src.llm_judge_baseline import run_baseline_over  # noqa: E402
from src.evaluate import score, print_report  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="path to full response.jsonl (default: use bundled sample)")
    ap.add_argument("--source", help="path to full source_info.jsonl")
    ap.add_argument("--n", type=int, default=None, help="limit number of examples (for a quick test)")
    ap.add_argument("--model", default="claude-sonnet-4-6")
    args = ap.parse_args()

    if args.data and args.source:
        examples = load_ragtruth_list(args.data, args.source, split="test")
    else:
        examples = load_sample(str(Path(__file__).resolve().parent.parent / "data" / "sample_ragtruth.jsonl"))

    if args.n:
        examples = examples[: args.n]

    print(f"Running LLM-judge baseline over {len(examples)} examples with {args.model}...")
    y_true, y_pred = run_baseline_over(examples, model=args.model)
    metrics = score(y_true, y_pred)
    print_report(metrics, name=f"llm_judge_baseline ({args.model})")


if __name__ == "__main__":
    main()
