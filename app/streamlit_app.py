"""
streamlit_app.py
Live demo: paste a context passage + a question, generate an answer, and see the
claim-by-claim faithfulness verdicts. This is the "show, don't tell" piece for your
Review demo -- it does NOT need the RAGTruth dataset at all.

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    streamlit run app/streamlit_app.py
"""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.claim_decompose import decompose_claims  # noqa: E402
from src.nli_verifier import NLIVerifier, response_is_hallucinated  # noqa: E402

st.set_page_config(page_title="RAG Faithfulness Checker", layout="wide")
st.title("RAG Faithfulness Checker")
st.caption("Paste a context + a generated answer. Each claim gets checked against the context.")


@st.cache_resource
def get_verifier():
    return NLIVerifier()


with st.form("check_form"):
    context = st.text_area("Context (what the answer should be grounded in)", height=200,
                            placeholder="Paste the retrieved passage(s) here...")
    answer = st.text_area("Answer to check", height=150,
                           placeholder="Paste the RAG-generated answer here...")
    threshold = st.slider("Contradiction threshold", 0.0, 1.0, 0.5, 0.05)
    submitted = st.form_submit_button("Check faithfulness")

if submitted:
    if not context.strip() or not answer.strip():
        st.warning("Please fill in both the context and the answer.")
    else:
        with st.spinner("Decomposing into claims..."):
            claims = decompose_claims(answer)

        if not claims:
            st.info("No checkable factual claims were found in this answer.")
        else:
            with st.spinner(f"Verifying {len(claims)} claim(s) against the context..."):
                verifier = get_verifier()
                verifications = verifier.verify_claims(claims, context)

            overall = response_is_hallucinated(verifications, contradiction_threshold=threshold)
            if overall:
                st.error("Overall verdict: likely contains unsupported / contradicted content")
            else:
                st.success("Overall verdict: appears grounded in the context")

            st.subheader("Claim-by-claim breakdown")
            for v in verifications:
                color = {"entailment": "green", "neutral": "orange", "contradiction": "red"}[v.label]
                st.markdown(f":{color}[**{v.label.upper()}**] &nbsp; {v.claim}")
                st.caption(
                    f"entailment={v.scores['entailment']:.2f}  "
                    f"neutral={v.scores['neutral']:.2f}  "
                    f"contradiction={v.scores['contradiction']:.2f}"
                )
                with st.expander("Best-matching context chunk"):
                    st.write(v.best_chunk)
