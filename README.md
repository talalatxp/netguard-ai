# NetGuard AI

NetGuard AI is an experimental, explainable network-intrusion detection project
built on labelled flow data from CIC-IDS2017. It classifies each network flow as
`BENIGN` or `ATTACK` and studies how evaluation methodology changes the apparent
ability of a supervised model to generalize.

> **Status:** active development. Dataset provenance and the first reproducible
> schema and label profile are complete. Data-quality auditing, preprocessing,
> model training, and final evaluation are not complete yet.

## Research question

How much does a supervised classifier's ability to detect malicious traffic
degrade when moving from a stratified random split to a strict day-based temporal
evaluation, and can it maintain a useful false-positive rate on later traffic?

The product objective and the experimental question are deliberately separate:

- **Product objective:** detect `ATTACK` flows while controlling false alarms.
- **Experimental question:** measure whether random-split results overestimate
  generalization to traffic observed later in time.

## Why this project

Very high intrusion-detection scores can be misleading when duplicated or highly
similar flows from the same scenario appear in both training and test data. This
project prioritizes reproducibility, leakage prevention, temporal evaluation,
error analysis, and honest limitations over reporting accuracy alone.

## Verified dataset snapshot

The project uses the official `MachineLearningCSV.zip` distribution published by
the Canadian Institute for Cybersecurity at the University of New Brunswick.
Raw data is stored locally under `data/raw/` and is never committed to Git.

| Property | Verified value |
| --- | ---: |
| CSV files | 8 |
| Rows | 2,830,743 |
| Columns | 79 |
| `BENIGN` flows | 2,273,097 |
| Attack flows | 557,646 |
| Raw attack labels | 14 |
| Structurally malformed rows | 0 |
| Identical schema across files | Yes |

Two rare labels require particular care when defining evaluation partitions:
`Heartbleed` has 11 rows and `Infiltration` has 36. The three `Web Attack`
labels also contain a replacement character in the official CSV data. These
issues are recorded as data-quality findings and will be normalized explicitly
without modifying the raw files.

See [the data documentation](data/README.md), the committed
[SHA-256 inventory](data/checksums.json), the written
[profile interpretation](reports/data-profile.md), and the generated
[data profile](reports/data-profile.json) for exact provenance and counts. The
[data-quality audit](reports/data-quality-audit.md) documents types, non-finite
values, exact duplicates, and the proposed cleaning policy.

## Experimental design

### Task

- Primary task: binary classification, `BENIGN` versus `ATTACK`.
- Secondary analysis: metrics grouped by each original attack label.
- Full multiclass attack classification is outside the initial scope.

### Evaluation A: random reference

- Fixed random seed `42`, targeting 70% train, 15% validation, and 15% test.
- Group-aware train, validation, and test partitions by exact feature hash;
  check class balance because mixed-label groups limit strict stratification.
- Included as a reference comparable with common introductory approaches.
- Not treated as sufficient evidence of temporal generalization.

### Evaluation B: temporal

- Chronological `train -> validation -> test` ordering.
- Frozen days: Monday–Wednesday train, Thursday validation, Friday test.
- Primary metrics cover all later rows remaining after the agreed exact
  full-row deduplication. Report metrics separately for feature hashes absent
  from earlier partitions.
- Later data is never used to fit transformations or models.
- Because attack families differ by day, this test combines temporal and
  unseen-attack generalization; a performance gap cannot isolate time alone.
- Attacks present during training and attacks absent from training will be
  reported separately.

### Leakage and final-test contract

- Imputation, scaling, feature selection, and models are fitted on training data
  only.
- Validation data is used for model configuration and threshold selection.
- All preprocessing, features, model settings, and the decision threshold are
  frozen before the final test evaluation.
- Final test results are not used to revise those decisions.

### Threshold and metrics

The decision threshold is selected on validation data. Candidate thresholds must
first achieve `ATTACK recall >= 0.80`; among those candidates, the threshold with
the highest `ATTACK` precision is selected.

Primary reporting includes:

- `ATTACK` precision, recall, and F1;
- PR-AUC;
- confusion matrix;
- false-positive rate and absolute false-positive count;
- results by day and original attack label.

Accuracy will never be reported on its own.

## Planned model comparison

1. `DummyClassifier` as a trivial reference.
2. Logistic regression as an interpretable learned baseline.
3. Random Forest.
4. Histogram-based gradient boosting.

No additional model will be added before the required evaluation, documentation,
and demo are complete.

## Repository contents

```text
netguard-ai/
├── README.md
├── data/
│   ├── README.md
│   ├── checksums.json
│   ├── processed/           # generated locally; ignored by Git
│   └── raw/                 # local only; ignored by Git
├── reports/
│   ├── data-profile.json
│   ├── data-profile.md
│   ├── data-quality-audit.json
│   ├── data-quality-audit.md
│   ├── feature-leakage-audit.json
│   ├── split-design.md
│   ├── split-summary.json
│   └── split-summary.md
└── scripts/
    ├── audit_dataset.py
    ├── audit_feature_leakage.py
    ├── hash_dataset.py
    └── profile_dataset.py
```

The repository will grow to include a tested Python package, experiment
configuration, model artifacts, an evaluation report, a model card, and a small
local inference demo. Planned components are not shown above as if they already
exist.

## Reproduce the current data checks

The current scripts use only the Python standard library. They have been verified
locally with Python 3.14. Detailed download instructions are in
[`data/README.md`](data/README.md).

After placing the official archive and its extracted CSV files under `data/raw/`,
regenerate the SHA-256 inventory:

```powershell
python scripts/hash_dataset.py data/raw/MachineLearningCSV.zip "data/raw/MachineLearningCSV/**/*.csv" --output data/checksums.json
```

Regenerate the schema and label profile:

```powershell
python scripts/profile_dataset.py "data/raw/MachineLearningCSV/**/*.csv" --output reports/data-profile.json
```

Audit exact repeated feature vectors and contradictory labels:

```powershell
python scripts/audit_feature_leakage.py "data/raw/MachineLearningCSV/**/*.csv" --output reports/feature-leakage-audit.json --groups-output reports/feature-leakage-groups.jsonl
```

The committed JSON contains totals and five examples per category. The complete
JSONL is generated locally and ignored by Git because it can be large. Its
one-based line numbers point to the original CSVs. The fingerprint excludes
`Label` and the redundant second `Fwd Header Length` column; it compares the
original feature-cell strings exactly, not numerically equivalent or similar
flows. Different files are flagged, but this audit alone does not establish
chronological order or whether a future split leaks data.
The [leakage-audit interpretation](reports/feature-leakage-audit.md) records the
evaluation policy for repeated vectors and conflicting labels.
The [split design](reports/split-design.md) records the frozen temporal days,
raw day-level counts, and the remaining reproducibility checks.

Build the deduplicated row manifest and both split assignments:

```powershell
python scripts/build_splits.py "data/raw/MachineLearningCSV/**/*.csv" --manifest-output data/processed/split-manifest.csv --report-output reports/split-summary.json
```

The manifest is a generated local artifact and is ignored by Git. The committed
[split summary](reports/split-summary.md) records its filename, size, SHA-256,
actual partition counts, and overlap checks. Rebuilding from the verified raw
files with the same code and seed must reproduce the same manifest hash.

Any checksum mismatch must be investigated before the affected file is used.

## Roadmap

- [x] Define the research question and experimental protocol.
- [x] Download and verify the official dataset distribution.
- [x] Record archive and per-file SHA-256 hashes.
- [x] Profile schemas, row counts, and labels.
- [x] Audit types, missing values, infinities, and duplicates.
- [x] Audit pre-split feature leakage risks and record evaluation safeguards.
- [x] Freeze and build random and temporal partitions; verify overlap controls.
- [ ] Build the preprocessing pipeline and learned baseline.
- [ ] Compare Random Forest and gradient boosting.
- [ ] Analyze errors, attack coverage, and feature importance.
- [ ] Build and test the local inference demo.
- [ ] Publish the final report, model card, and reproducible release.

## Limitations and intended use

NetGuard AI is a research and portfolio prototype, not a production intrusion
detection system. CIC-IDS2017 was captured in a controlled environment in 2017,
so performance on this dataset does not establish effectiveness on current,
real-world networks or previously unseen attacks. The project will not capture
live packets, block connections, or make operational security guarantees.

## Dataset attribution

Dataset: [CIC-IDS2017, Canadian Institute for Cybersecurity, University of New
Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html).

Please cite the paper requested by the dataset publisher:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani. "Toward
> Generating a New Intrusion Detection Dataset and Intrusion Traffic
> Characterization." ICISSP, 2018.
