"""
make_sample_data.py
Builds a small, stratified sample of RAGTruth (balanced across task_type x
hallucinated/clean) for quick local testing without cloning the full ~36MB corpus.

Usage:
    python scripts/make_sample_data.py \
        /path/to/RAGTruth/dataset/response.jsonl \
        /path/to/RAGTruth/dataset/source_info.jsonl \
        data/sample_ragtruth.jsonl \
        --per_bucket 20
"""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data_loader import load_ragtruth_list  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("response_path")
    ap.add_argument("source_info_path")
    ap.add_argument("out_path")
    ap.add_argument("--per_bucket", type=int, default=20,
                     help="examples per (task_type x hallucinated/clean) bucket")
    ap.add_argument("--split", default="test")
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    random.seed(args.seed)
    examples = load_ragtruth_list(args.response_path, args.source_info_path, split=args.split)

    buckets = {}
    for e in examples:
        buckets.setdefault((e.task_type, e.is_hallucinated), []).append(e)

    sample = []
    for key, items in buckets.items():
        random.shuffle(items)
        sample.extend(items[: args.per_bucket])
    random.shuffle(sample)

    Path(args.out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out_path, "w", encoding="utf-8") as f:
        for e in sample:
            f.write(json.dumps({
                "response_id": e.response_id,
                "source_id": e.source_id,
                "model": e.model,
                "split": e.split,
                "task_type": e.task_type,
                "source": e.source,
                "context": e.context,
                "response": e.response,
                "is_hallucinated": e.is_hallucinated,
                "label_types": e.label_types,
            }) + "\n")

    print(f"Wrote {len(sample)} examples to {args.out_path}")
    for key, items in sorted(buckets.items(), key=lambda kv: kv[0]):
        print(f"  {key}: took {min(len(items), args.per_bucket)} of {len(items)} available")


if __name__ == "__main__":
    main()
