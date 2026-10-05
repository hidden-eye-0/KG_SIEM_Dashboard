# RAG Hallucination / Faithfulness Detector

Claim-level faithfulness checker for RAG systems: decomposes a generated answer into
atomic claims, verifies each one against the retrieved context with a pretrained NLI
model, and flags the response if any claim is unsupported or contradicted.

Built for the SWE1017 NLP course project. Dataset: [RAGTruth](https://github.com/ParticleMedia/RAGTruth)
(Niu et al., ACL 2024) — ~18,000 human-annotated RAG responses across QA, summarization,
and data-to-text generation.

## Project layout

```
src/
  data_loader.py        merges RAGTruth's response.jsonl + source_info.jsonl
  claim_decompose.py     LLM-based claim decomposition (cached to disk)
  nli_verifier.py         zero-shot NLI verification (chunked context)
  llm_judge_baseline.py   simple LLM-as-judge baseline for comparison
  pipeline.py             ties decomposition + verification together
  evaluate.py             precision/recall/F1/balanced accuracy scoring
scripts/
  make_sample_data.py     builds the stratified sample below (already run once)
  run_baseline.py         run the LLM-judge baseline end to end
  run_pipeline_eval.py    run the full claim+NLI pipeline end to end
app/
  streamlit_app.py        live demo dashboard (doesn't need RAGTruth at all)
data/
  sample_ragtruth.jsonl   120 real examples pulled from RAGTruth's test split,
                          stratified across task_type x hallucinated/clean
                          (20 per bucket) — for testing without a 36MB clone
```

Every module in `src/` was written and unit-tested against the **actual** RAGTruth
schema (cloned from the official repo) before this was handed to you — field names,
label structure, and the sample data are all real, not invented.

## Setup

```bash
python -m venv venv && source venv/bin/activate   # or just use Google Colab
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...                 # any provider works, see note below
```

No local GPU needed — the NLI model (DeBERTa-v3-base, ~370MB) runs fine on CPU for
this scale, and Colab's free T4 is more than enough if you want to fine-tune later.

**Using OpenAI instead of Anthropic:** `src/claim_decompose.py` and
`src/llm_judge_baseline.py` each have a `client` parameter and a comment marking the
one API call to swap out. Everything else (caching, parsing, evaluation) is
provider-agnostic.

## Run order

**1. Baseline first** (no model download, just an API key — validates your eval harness):
```bash
python scripts/run_baseline.py --n 30      # quick smoke test on 30 examples
python scripts/run_baseline.py             # full 120-example bundled sample
```

**2. Full pipeline** (downloads the NLI model on first run):
```bash
python scripts/run_pipeline_eval.py --n 20
python scripts/run_pipeline_eval.py
```
Compare its F1 / balanced accuracy against the baseline from step 1 — that delta is
your "was the extra complexity worth it" number for the report.

**3. Tune the threshold** — sweep `--threshold` (0.3 to 0.7) and re-run to find the
best precision/recall tradeoff on the sample before locking it in:
```bash
python scripts/run_pipeline_eval.py --threshold 0.3
python scripts/run_pipeline_eval.py --threshold 0.7
```

**4. Scale up to the full dataset** once the pipeline works on the sample:
```bash
git clone https://github.com/ParticleMedia/RAGTruth.git
python scripts/run_pipeline_eval.py \
    --data RAGTruth/dataset/response.jsonl \
    --source RAGTruth/dataset/source_info.jsonl
```

**5. Generalization test (your novelty result)** — run your *already-trained* threshold
and verifier against an out-of-domain benchmark without retraining, and report the
accuracy drop. Easiest option: [MiniCheck's `LLM-AggreFact`](https://github.com/Liyan06/MiniCheck)
benchmark on Hugging Face (`lytang/LLM-AggreFact`) or [FaithBench](https://github.com/vectara/FaithBench).
Write a small adapter that maps their fields into the same shape as `RagTruthExample`
(`context`, `response`, `is_hallucinated`) and reuse `HallucinationPipeline` and
`src/evaluate.py` unchanged — that's the whole point of keeping those two decoupled
from the RAGTruth-specific loader.

**6. Live demo**:
```bash
streamlit run app/streamlit_app.py
```

## Notes on the numbers you'll get

- RAGTruth's own paper reports response-level F1 around 63–64% for prompted GPT-4,
  58.8% for SelfCheckGPT, and 78.7% for a Llama-2-13B fine-tuned on RAGTruth's training
  split. Your zero-shot NLI pipeline won't match the fine-tuned number out of the box —
  that gap *is* the motivation for fine-tuning in step 7 if you have time.
- Span-level detection is hard even for GPT-4-turbo in the original paper (low
  precision). Don't be surprised if your claim-level verdicts are noisy — that's
  consistent with the literature, not a bug in your code.
- `.cache/claims/` and `.cache/judge/` will fill up with one JSON file per unique
  text you've decomposed/judged — safe to delete between runs if you change the prompt.
