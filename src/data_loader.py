"""
data_loader.py
Loads and merges RAGTruth's response.jsonl + source_info.jsonl into unified examples.

Schema confirmed directly against github.com/ParticleMedia/RAGTruth (dataset/*.jsonl):

response.jsonl:
    id            str    unique response id
    source_id     str    joins to source_info.jsonl
    model         str    generator model, e.g. "gpt-4-0613", "mistral-7B-instruct"
    temperature   float
    labels        list   span-level hallucination annotations (empty list = no hallucination)
                         each label: {start, end, text, meta, label_type,
                                      implicit_true, due_to_null}
                         label_type examples: "Evident Conflict", "Subtle Conflict",
                                              "Evident Baseless Info", "Subtle Baseless Info"
    split         str    "train" | "test"
    quality       str    "good" | "incorrect_refusal" | "truncated"
    response      str    the generated text being checked

source_info.jsonl:
    source_id     str
    task_type     str    "QA" | "Summary" | "Data2txt"
    source        str    "MARCO" | "CNN/DM" | "Yelp" | "Recent News"
    source_info   str    the retrieved/reference context the response should be grounded in
    prompt        str    full prompt given to the generator
"""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional


@dataclass
class RagTruthExample:
    response_id: str
    source_id: str
    model: str
    split: str
    quality: str
    task_type: str
    source: str
    context: str            # the grounding document/context (source_info)
    response: str           # the generated answer to check
    is_hallucinated: bool   # ground truth: True if `labels` is non-empty
    label_types: List[str]  # e.g. ["Evident Conflict", "Evident Baseless Info"]
    raw_labels: list        # full span annotations, for span-level analysis later


def load_ragtruth(
    response_path: str,
    source_info_path: str,
    split: Optional[str] = None,
    only_good_quality: bool = True,
) -> Iterator[RagTruthExample]:
    """Stream merged RAGTruth examples.

    split: "train", "test", or None for both.
    only_good_quality: drop rows RAGTruth itself flagged as truncated/incorrect_refusal
                        (144 + 29 out of 17,790 rows) -- these aren't real hallucination
                        signal, they're generation failures.
    """
    sources = {}
    with open(source_info_path, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            sources[row["source_id"]] = row

    with open(response_path, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            if split is not None and row["split"] != split:
                continue
            if only_good_quality and row["quality"] != "good":
                continue
            src = sources.get(row["source_id"])
            if src is None:
                continue  # shouldn't happen on the real corpus, but don't crash a run over it
            yield RagTruthExample(
                response_id=row["id"],
                source_id=row["source_id"],
                model=row["model"],
                split=row["split"],
                quality=row["quality"],
                task_type=src["task_type"],
                source=src["source"],
                context=src["source_info"],
                response=row["response"],
                is_hallucinated=len(row["labels"]) > 0,
                label_types=[l["label_type"] for l in row["labels"]],
                raw_labels=row["labels"],
            )


def load_ragtruth_list(response_path: str, source_info_path: str, **kwargs) -> List[RagTruthExample]:
    return list(load_ragtruth(response_path, source_info_path, **kwargs))

def context_to_text(context):
    """Convert structured context dictionaries into plain text."""
    if isinstance(context, str):
        return context

    if isinstance(context, dict):
        parts = []

        if context.get("name"):
            parts.append(f"Name: {context['name']}")

        if context.get("address"):
            parts.append(f"Address: {context['address']}")

        if context.get("city"):
            parts.append(f"City: {context['city']}")

        if context.get("state"):
            parts.append(f"State: {context['state']}")

        if context.get("categories"):
            parts.append(f"Categories: {context['categories']}")

        if context.get("business_stars") is not None:
            parts.append(f"Rating: {context['business_stars']}")

        if context.get("hours"):
            parts.append(f"Hours: {context['hours']}")

        if context.get("attributes"):
            parts.append(f"Attributes: {context['attributes']}")

        if context.get("review_info"):
            for review in context["review_info"]:
                if isinstance(review, dict):
                    if review.get("review_stars") is not None:
                        parts.append(f"Review rating: {review['review_stars']}")
                    if review.get("review_text"):
                        parts.append(f"Review: {review['review_text']}")

        return "\n".join(parts)

    return str(context)

def load_sample(sample_path: str) -> List[RagTruthExample]:
    """Load the pre-built data/sample_ragtruth.jsonl bundled with this project
    (already merged/flattened -- see scripts/make_sample_data.py)."""
    examples = []
    with open(sample_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            examples.append(RagTruthExample(
                response_id=d["response_id"],
                source_id=d.get("source_id", ""),
                model=d.get("model", ""),
                split=d.get("split", ""),
                quality=d.get("quality", "good"),
                task_type=d["task_type"],
                source=d["source"],
                context=context_to_text(d["context"]),
                response=d["response"],
                is_hallucinated=d["is_hallucinated"],
                label_types=d.get("label_types", []),
                raw_labels=d.get("raw_labels", []),
            ))
    return examples


if __name__ == "__main__":
    import sys
    resp, src = sys.argv[1], sys.argv[2]
    examples = load_ragtruth_list(resp, src, split="test")
    print(f"Loaded {len(examples)} test examples")
    hallucinated = sum(e.is_hallucinated for e in examples)
    print(f"  hallucinated: {hallucinated} ({hallucinated/len(examples):.1%})")
    print(f"  clean:        {len(examples) - hallucinated}")
    print("\nExample:")
    print(examples[0])
