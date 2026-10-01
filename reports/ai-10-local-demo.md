# AI-10 local explanatory demo

## Scope

AI-10 adds a local Streamlit interface for inspecting predictions from the six
frozen learned-model configurations produced by AI-07 and AI-08. The default is
the group-aware random Histogram Gradient Boosting model because it has the
strongest practical random-test F1, but the interface keeps the evaluation name
visible and exposes every learned random and temporal configuration.

The demo does not capture network traffic, retrain a model, change a threshold,
identify attack families, or make an operational security decision. It is a
portfolio and research-explanation surface for already frozen artifacts.

## User flow

1. Select a frozen model and evaluation in the sidebar.
2. Review its validation-selected threshold, artifact-hash prefix, frozen test
   metrics, and model-specific limitation.
3. Download the header-only 69-feature CSV template.
4. Upload a prepared CSV containing up to 10,000 rows.
5. Review each row's attack score, frozen threshold, and binary decision.
6. Download the scored result as CSV.
7. Inspect the selected model's top validation permutation features as global
   context, not as a causal explanation for an individual row.

## Input and artifact safety

- The input must contain exactly the 69 prepared feature columns recorded in
  the frozen split summary. An optional `Label` column is ignored.
- Surrounding header whitespace is normalized; duplicate, missing, or extra
  columns stop the batch.
- Every feature must be numeric. One malformed value rejects the complete batch;
  rows are never silently skipped.
- The web upload is limited to 25 MB and inference is limited to 10,000 rows per
  batch.
- Non-finite numeric values follow the frozen model preprocessing contract.
- Before deserialization, the selected artifact's complete SHA-256 is compared
  with the committed experiment record.
- Raw input rows are processed in the local Streamlit process and are not
  written by the application.

## Decision output

The model output is labelled `attack_score`, not real-world attack probability.
The binary result is calculated only as:

```text
ATTACK if attack_score >= frozen validation threshold; otherwise BENIGN
```

The threshold is displayed for every result row. The user cannot adjust it in
the interface, preventing the demo from silently revising the frozen experiment.

## Run locally

The ignored model artifacts must already exist under `models/ai-07/` and
`models/ai-08/`. They can be reproduced with the AI-07 and AI-08 commands in the
project README.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://localhost:8501`, download the CSV template, populate one or more
prepared rows, and upload the file.

## Verification

- Core unit tests cover schema ordering, optional labels, malformed values,
  missing and extra fields, frozen-threshold decisions, six-model registry
  construction, and artifact-hash rejection.
- Streamlit integration tests verify startup, the default frozen model, upload
  availability, and an end-to-end one-row prediction using the real HGB artifact.
- The application was also inspected in a real browser with the local Streamlit
  server running.

## Limitations

- CIC-IDS2017 is controlled 2017 traffic and is not representative of all
  current networks.
- AI-09 demonstrated severe score and threshold instability across days and
  unseen attack families.
- Permutation importance is global, validation-based, and correlational.
- The demo accepts prepared flow features, not PCAP files or live packets.
- A production system would require current representative data, monitoring,
  calibration, threat-model review, authentication, and operational controls.
