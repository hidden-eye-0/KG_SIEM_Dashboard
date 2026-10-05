"""
llm_judge_baseline.py
The simplest possible hallucination detector: ask an LLM "is this response fully
supported by this context, yes or no?" No claim decomposition, no NLI model.

Run this FIRST, before building anything fancier -- it's your sanity check that the
eval harness (data loading + scoring) works, and it's the baseline your claim+NLI
pipeline needs to beat to justify the extra complexity.

Requires: pip install anthropic
Set your key:  export ANTHROPIC_API_KEY=sk-ant-...
"""
import hashlib
import json
import os
from pathlib import Path

CACHE_DIR = Path(".cache/judge")

_JUDGE_PROMPT = """Context:
\"\"\"{context}\"\"\"

Response to check:
\"\"\"{response}\"\"\"

Does the response contain ANY claim that is not supported by, or that contradicts, the
context? Answer with exactly one word: YES or NO.
"""


def _cache_key(context: str, response: str) -> str:
    return hashlib.sha256((context + "||" + response).encode("utf-8")).hexdigest()


def judge_is_hallucinated(
    context: str,
    response: str,
    client=None,
    model: str = "claude-sonnet-4-6",
    use_cache: bool = True,
    cache_dir: Path = CACHE_DIR,
) -> bool:
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = _cache_key(context, response)
    cache_file = cache_dir / f"{key}.json"
    if use_cache and cache_file.exists():
        return json.loads(cache_file.read_text())

    if client is None:
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    msg = client.messages.create(
        model=model,
        max_tokens=8,
        messages=[{"role": "user", "content": _JUDGE_PROMPT.format(context=context, response=response)}],
    )
    raw = "".join(block.text for block in msg.content if block.type == "text").strip().upper()
    verdict = raw.startswith("YES")

    if use_cache:
        cache_file.write_text(json.dumps(verdict))
    return verdict


def run_baseline_over(examples, client=None, model: str = "claude-sonnet-4-6",
                       use_cache: bool = True, show_progress: bool = True):
    """examples: list of RagTruthExample (see src/data_loader.py).
    Returns (y_true, y_pred) lists ready for src/evaluate.py."""
    y_true, y_pred = [], []
    for i, ex in enumerate(examples):
        if show_progress and i % 20 == 0:
            print(f"  judging {i}/{len(examples)}...")
        pred = judge_is_hallucinated(ex.context, ex.response, client=client,
                                      model=model, use_cache=use_cache)
        y_true.append(ex.is_hallucinated)
        y_pred.append(pred)
    return y_true, y_pred


if __name__ == "__main__":
    print(_JUDGE_PROMPT.format(context="<context here>", response="<response here>"))
