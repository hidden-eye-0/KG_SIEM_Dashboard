"""
pipeline.py
End-to-end claim-level hallucination detector:
  response -> decompose into claims -> verify each claim against context (NLI) ->
  aggregate into one response-level hallucination flag.

This is what you compare against src/llm_judge_baseline.py (simpler, coarser) and,
if you get to it, against a RAGTruth-fine-tuned model (better, more work).
"""
from dataclasses import dataclass
from typing import List, Optional

from src.claim_decompose import decompose_claims
from src.nli_verifier import NLIVerifier, VerificationResult, response_is_hallucinated


@dataclass
class PipelineResult:
    response_id: str
    claims: List[str]
    verifications: List[VerificationResult]
    predicted_hallucinated: bool


class HallucinationPipeline:
    def __init__(self, nli_verifier: Optional[NLIVerifier] = None,
                 llm_client=None, decompose_model: str = "claude-sonnet-4-6",
                 contradiction_threshold: float = 0.5, flag_unsupported: bool = True,
                 use_cache: bool = True):
        # Lazy-load the NLI model only when the pipeline actually needs it -- keeps
        # `import src.pipeline` cheap for scripts that only want the dataclasses.
        self._verifier = nli_verifier
        self.llm_client = llm_client
        self.decompose_model = decompose_model
        self.contradiction_threshold = contradiction_threshold
        self.flag_unsupported = flag_unsupported
        self.use_cache = use_cache

    @property
    def verifier(self) -> NLIVerifier:
        if self._verifier is None:
            self._verifier = NLIVerifier()
        return self._verifier

    def run_one(self, response_id: str, response_text: str, context: str) -> PipelineResult:
        claims = decompose_claims(
            response_text, client=self.llm_client, model=self.decompose_model,
            use_cache=self.use_cache,
        )
        if not claims:
            # Nothing checkable -> nothing to flag. Don't silently mark this
            # "hallucinated" or "clean"; log it if you see it happen a lot.
            return PipelineResult(response_id, claims=[], verifications=[],
                                   predicted_hallucinated=False)

        verifications = self.verifier.verify_claims(claims, context)
        predicted = response_is_hallucinated(
            verifications,
            contradiction_threshold=self.contradiction_threshold,
            flag_unsupported=self.flag_unsupported,
        )
        return PipelineResult(response_id, claims, verifications, predicted)

    def run_over(self, examples, show_progress: bool = True) -> List[PipelineResult]:
        """examples: list of RagTruthExample (see src/data_loader.py)."""
        results = []
        for i, ex in enumerate(examples):
            if show_progress and i % 10 == 0:
                print(f"  pipeline {i}/{len(examples)}...")
            results.append(self.run_one(ex.response_id, ex.response, ex.context))
        return results


if __name__ == "__main__":
    # Import check only -- building the real NLIVerifier requires downloading model
    # weights (see src/nli_verifier.py docstring), so we don't do that on import.
    print("pipeline.py imported OK:", HallucinationPipeline)
