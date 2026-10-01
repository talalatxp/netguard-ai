"""Local explanatory Streamlit demo for frozen NetGuard AI models."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))

from inference import (  # noqa: E402
    InputValidationError,
    load_feature_names,
    load_model_specs,
    load_verified_model,
    predict_rows,
    prepare_input_frame,
)


st.set_page_config(
    page_title="NetGuard AI Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(135deg, #07111f 0%, #0b1728 55%, #101c2d 100%); }
    [data-testid="stHeader"] { background: transparent; }
    .hero {
        padding: 1.6rem 1.8rem;
        border: 1px solid rgba(83, 215, 181, 0.24);
        border-radius: 18px;
        background: linear-gradient(120deg, rgba(18, 44, 66, 0.95), rgba(12, 30, 49, 0.95));
        margin-bottom: 1rem;
    }
    .hero-kicker { color: #53d7b5; font-size: .8rem; font-weight: 700; letter-spacing: .14em; }
    .hero h1 { margin: .25rem 0 .5rem; font-size: 2.25rem; }
    .hero p { color: #b9c8d8; margin: 0; max-width: 760px; }
    .disclaimer {
        border-left: 4px solid #f2b84b; padding: .75rem 1rem;
        background: rgba(242, 184, 75, .08); border-radius: 4px 12px 12px 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def feature_names() -> tuple[str, ...]:
    return load_feature_names(ROOT / "reports" / "split-summary.json")


@st.cache_data
def model_specs():
    return load_model_specs(
        ROOT / "reports" / "ai-07-baseline-results.json",
        ROOT / "reports" / "ai-08-model-comparison-results.json",
        ROOT / "reports" / "ai-09-error-analysis.json",
        ROOT,
    )


@st.cache_resource
def cached_model(model_key: str, artifact_hash: str):
    spec = model_specs()[model_key]
    if spec.artifact_sha256 != artifact_hash:
        raise ValueError("model selection changed while loading the artifact")
    return load_verified_model(spec)


st.markdown(
    """
    <section class="hero">
      <div class="hero-kicker">EXPERIMENTAL FLOW CLASSIFIER</div>
      <h1>NetGuard AI Lab</h1>
      <p>Inspect how a frozen CIC-IDS2017 model scores prepared network-flow rows.
      Every decision shows the model score and the validation-selected threshold.</p>
    </section>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="disclaimer"><strong>Research demo only.</strong> The score is not a
    calibrated real-world attack probability. This app does not capture traffic,
    block connections, retrain models, or provide an operational security decision.</div>
    """,
    unsafe_allow_html=True,
)

specs = model_specs()
with st.sidebar:
    st.header("Frozen experiment")
    selected_key = st.selectbox(
        "Model and evaluation",
        options=list(specs),
        index=list(specs).index("random:hist_gradient_boosting"),
        format_func=lambda key: specs[key].display_name,
    )
    selected = specs[selected_key]
    st.caption(selected.caveat)
    st.divider()
    st.metric("Frozen threshold", f"{selected.threshold:.6f}")
    st.caption(f"Artifact SHA-256: `{selected.artifact_sha256[:12]}…`")

test_metrics = selected.test_metrics
st.subheader("Recorded test evidence")
metric_columns = st.columns(4)
metric_columns[0].metric("ATTACK precision", f"{test_metrics['attack_precision']:.1%}")
metric_columns[1].metric("ATTACK recall", f"{test_metrics['attack_recall']:.1%}")
metric_columns[2].metric("F1", f"{test_metrics['attack_f1']:.3f}")
metric_columns[3].metric("False positives", f"{test_metrics['false_positive_count']:,}")
st.caption(
    "These are frozen dataset results, not a guarantee for uploaded or live traffic."
)

expected_features = feature_names()
template = pd.DataFrame(columns=expected_features).to_csv(index=False).encode("utf-8")
left, right = st.columns([1.5, 1], gap="large")
with left:
    st.subheader("Score a prepared CSV")
    uploaded = st.file_uploader(
        "Upload up to 10,000 rows with the 69 frozen feature columns",
        type=["csv"],
        accept_multiple_files=False,
        help="An optional Label column is ignored. Any malformed value rejects the complete batch.",
    )
with right:
    st.subheader("Input contract")
    st.write("Use the exact prepared schema. Download the header-only template:")
    st.download_button(
        "Download CSV template",
        data=template,
        file_name="netguard-flow-template.csv",
        mime="text/csv",
        width="stretch",
    )

if uploaded is None:
    st.info("Upload a prepared flow CSV to run local inference.")
else:
    try:
        raw_frame = pd.read_csv(io.BytesIO(uploaded.getvalue()))
        prepared = prepare_input_frame(raw_frame, expected_features)
        model = cached_model(selected.key, selected.artifact_sha256)
        results = predict_rows(model, prepared, selected.threshold)
    except (InputValidationError, FileNotFoundError, ValueError) as error:
        st.error(str(error))
    except pd.errors.ParserError as error:
        st.error(f"The CSV could not be parsed. The batch was not scored: {error}")
    else:
        attack_count = int((results["prediction"] == "ATTACK").sum())
        summary_columns = st.columns(3)
        summary_columns[0].metric("Rows scored", f"{len(results):,}")
        summary_columns[1].metric("Flagged ATTACK", f"{attack_count:,}")
        summary_columns[2].metric("Flagged rate", f"{attack_count / len(results):.1%}")

        st.subheader("Row decisions")
        st.dataframe(
            results.style.format(
                {"attack_score": "{:.6f}", "frozen_threshold": "{:.6f}"}
            ),
            width="stretch",
            hide_index=True,
        )
        st.download_button(
            "Download scored results",
            data=results.to_csv(index=False).encode("utf-8"),
            file_name="netguard-scored-results.csv",
            mime="text/csv",
        )

        counts, boundaries = np.histogram(results["attack_score"], bins=np.linspace(0, 1, 21))
        histogram = pd.DataFrame(
            {
                "score range": [
                    f"{boundaries[index]:.2f}–{boundaries[index + 1]:.2f}"
                    for index in range(len(counts))
                ],
                "rows": counts,
            }
        ).set_index("score range")
        st.subheader("Attack-score distribution")
        st.bar_chart(histogram)

st.subheader("Global validation context")
st.caption(
    "Permutation importance describes validation ranking for the selected model. "
    "It is global, correlational, and not an explanation of an individual row."
)
importance = pd.DataFrame(
    selected.important_features, columns=["feature", "mean PR-AUC drop"]
).set_index("feature")
st.bar_chart(importance)

with st.expander("What this demo can and cannot show"):
    st.markdown(
        """
        - It reproduces decisions from one frozen model artifact and threshold.
        - It validates the complete batch before scoring; malformed rows are not skipped.
        - It does not identify an attack family or explain causality.
        - Temporal results show that scores and thresholds can fail on later traffic.
        - A production IDS would require current data, monitoring, calibration, and security review.
        """
    )
