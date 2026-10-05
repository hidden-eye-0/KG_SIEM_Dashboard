"""
nli_verifier.py
Zero-shot claim verification against retrieved context using a pretrained NLI model.

For each (claim, context) pair we split the context into overlapping word chunks -- a
stand-in for "retrieved passages" -- run NLI on each chunk as premise / claim as
hypothesis, and keep the chunk with the strongest entailment signal. This mirrors how a
real RAG verifier checks a claim against multiple retrieved passages instead of one
giant document (RAGTruth's `source_info` is often longer than a single 512-token window).

Requires: pip install torch transformers
First run will download ~370MB of model weights from the Hugging Face Hub.
"""
from dataclasses import dataclass
from typing import List

MODEL_NAME = "MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli"


@dataclass
class VerificationResult:
    claim: str
    label: str      # "entailment" | "neutral" | "contradiction"
    scores: dict     # {"entailment": p, "neutral": p, "contradiction": p}
    best_chunk: str


def chunk_text(context: str, chunk_size: int = 400, overlap: int = 50) -> List[str]:
    """Split context into overlapping word-count chunks. Pure function, no model
    dependency, so it's testable without downloading anything."""
    words = context.split()
    if len(words) <= chunk_size:
        return [context]
    chunks = []
    step = max(1, chunk_size - overlap)
    for i in range(0, len(words), step):
        chunk = " ".join(words[i:i + chunk_size])
        chunks.append(chunk)
        if i + chunk_size >= len(words):
            break
    return chunks


class NLIVerifier:
    def __init__(self, model_name: str = MODEL_NAME, device: str = None,
                 chunk_size: int = 400, chunk_overlap: int = 50):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name).to(self.device)
        self.model.eval()
        # MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli label order (see model card config.json):
        # 0=entailment, 1=neutral, 2=contradiction
        self.id2label = {0: "entailment", 1: "neutral", 2: "contradiction"}
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def verify_claim(self, claim: str, context: str) -> VerificationResult:
        chunks = chunk_text(context, self.chunk_size, self.chunk_overlap)
        best_chunk, best_scores = None, None
        with self.torch.no_grad():
            for chunk in chunks:
                inputs = self.tokenizer(chunk, claim, return_tensors="pt",
                                         truncation=True, max_length=512).to(self.device)
                logits = self.model(**inputs).logits[0]
                probs = self.torch.softmax(logits, dim=-1).tolist()
                scores = {self.id2label[i]: p for i, p in enumerate(probs)}
                # keep whichever chunk most confidently supports the claim
                if best_scores is None or scores["entailment"] > best_scores["entailment"]:
                    best_chunk, best_scores = chunk, scores
        label = max(best_scores, key=best_scores.get)
        return VerificationResult(claim=claim, label=label, scores=best_scores, best_chunk=best_chunk)

    def verify_claims(self, claims: List[str], context: str) -> List[VerificationResult]:
        return [self.verify_claim(c, context) for c in claims]


def response_is_hallucinated(
    results: List[VerificationResult],
    contradiction_threshold: float = 0.5,
    flag_unsupported: bool = True,
) -> bool:
    """Aggregate claim-level verdicts into one response-level flag."""

    if not results:
        return False

    for r in results:
        # Strong contradiction
        if r.scores["contradiction"] >= contradiction_threshold:
            return True

        # Unsupported / neutral claim
        if flag_unsupported and r.label == "neutral":
            return True

    return False

if __name__ == "__main__":
    # Exercises chunk_text only -- no model download needed.
    long_context = " ".join(f"word{i}" for i in range(1000))
    chunks = chunk_text(long_context, chunk_size=400, overlap=50)
    print(f"{len(long_context.split())} words -> {len(chunks)} chunks")
    for c in chunks:
        print(f"  chunk: {len(c.split())} words")
