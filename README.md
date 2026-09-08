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
[SHA-256 inventory](data/checksums.json), and the generated
[data profile](reports/data-profile.json) for exact provenance and counts.

## Experimental design

### Task

- Primary task: binary classification, `BENIGN` versus `ATTACK`.
- Secondary analysis: metrics grouped by each original attack label.
- Full multiclass attack classification is outside the initial scope.

### Evaluation A: random reference

- Fixed random seed.
- Stratified train, validation, and test partitions.
- Included as a reference comparable with common introductory approaches.
- Not treated as sufficient evidence of temporal generalization.

### Evaluation B: temporal

- Chronological `train -> validation -> test` ordering.
- Later data is never used to fit transformations or models.
- Exact day assignments will be frozen after exploratory analysis of volume,
  class balance, attack coverage, and rare labels.
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
│   └── raw/                 # local only; ignored by Git
├── reports/
│   └── data-profile.json
└── scripts/
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

Any checksum mismatch must be investigated before the affected file is used.

## Roadmap

- [x] Define the research question and experimental protocol.
- [x] Download and verify the official dataset distribution.
- [x] Record archive and per-file SHA-256 hashes.
- [x] Profile schemas, row counts, and labels.
- [ ] Audit types, missing values, infinities, and duplicates.
- [ ] Audit features for leakage risk.
- [ ] Freeze random and temporal partitions.
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
