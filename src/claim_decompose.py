
import hashlib
import json
import os
from pathlib import Path
from typing import List, Optional

CACHE_DIR = Path(".cache/claims")

_DECOMPOSE_PROMPT = """Split the following text into a numbered list of atomic factual claims.


\"\"\"{text}\"\"\"
"""


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_numbered_list(raw: str) -> List[str]:
    if not raw:
        return []

    claims = []

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        for sep in [". ", ") "]:
            head = line[:5]
            if sep in head:
                line = line.split(sep, 1)[1]
                break
        line = line.lstrip("-\u2022 ").strip()
        if line:
            claims.append(line)
    return claims


def decompose_claims(
    text: str,
    client=None,
    model="gemini-3.6-flash" ,
    use_cache: bool = True,
    cache_dir: Path = CACHE_DIR,
) -> List[str]:
    """Return a list of atomic claim strings extracted from `text`."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = _cache_key(text)
    cache_file = cache_dir / f"{key}.json"
    if use_cache and cache_file.exists():
        return json.loads(cache_file.read_text())

    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ["GEMINI_API_KEY"],
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    )
    # ANTHROPIC: swap this call (and the response-parsing line below) for another provider
    msg = client.chat.completions.create(
        model=model,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": _DECOMPOSE_PROMPT.format(text=text)
            }
        ],
    )
    raw = msg.choices[0].message.content

    if not raw:
        print("Warning: Gemini returned an empty response. No claims extracted.")
        claims = []
    else:
        claims = _parse_numbered_list(raw)
        if use_cache:
            cache_file.write_text(json.dumps(claims))
        return claims


def decompose_many(
    texts: List[str],
    client=None,
    model="gemini-3.6-flash" ,
    use_cache: bool = True,
    cache_dir: Path = CACHE_DIR,
    show_progress: bool = True,
) -> List[List[str]]:
    results = []
    for i, t in enumerate(texts):
        if show_progress and i % 10 == 0:
            print(f"  decomposing {i}/{len(texts)}...")
        results.append(decompose_claims(t, client=client, model=model,
                                         use_cache=use_cache, cache_dir=cache_dir))
    return results


if __name__ == "__main__":
    # This part needs no API key -- it only exercises the parser.
    fake_llm_output = (
        "1. The Anne Frank House released new research.\n"
        "2) Anne Frank and Margot died earlier than previously believed.\n"
        "- The sisters were previously thought to have died in March 1945.\n"
    )
    print(_parse_numbered_list(fake_llm_output))
