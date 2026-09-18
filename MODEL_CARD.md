# NetGuard AI model card

## Model details

- **Name:** NetGuard AI
- **Version:** 0.1.0
- **Released:** 2026-09-18
- **Type:** binary network-flow classifiers
- **Framework:** scikit-learn 1.9.1
- **Language:** Python 3.14
- **Output:** `BENIGN` or `ATTACK`, plus an uncalibrated attack score
- **Status:** research and portfolio prototype; not production-ready

NetGuard AI contains frozen Logistic Regression, Random Forest, and Histogram
Gradient Boosting (HGB) pipelines for two evaluation settings. The group-aware
random setting measures an optimistic within-dataset reference. The temporal
setting trains on Monday-Wednesday, validates on Thursday, and tests on Friday.

## Intended use

The models are intended for:

- studying leakage-safe evaluation on CIC-IDS2017;
- comparing random and day-based temporal generalization;
- demonstrating reproducible preprocessing, threshold selection, and reporting;
- powering the local explanatory Streamlit demo.

They are not intended to monitor live traffic, block connections, replace an
analyst, provide operational security guarantees, or classify specific attack
families.

## Data

The project uses the official CIC-IDS2017 `MachineLearningCSV.zip` snapshot.
The archive and eight extracted CSV files are identified by SHA-256 in
`data/checksums.json`. Raw data is not redistributed by this repository.

After deterministic exact-row deduplication, 2,522,362 rows and 69 numeric
features remain. Repeated feature vectors are assigned to one random partition
by stable `seed + feature_hash` grouping. Conflicting labels are preserved.

| Evaluation | Train | Validation | Test |
| --- | ---: | ---: | ---: |
| Group-aware random | 1,765,722 | 377,894 | 378,746 |
| Temporal | 1,527,339 | 398,717 | 596,306 |

All Thursday validation and Friday test attack families are absent from temporal
training. Monday-Wednesday contain seven attack families, Thursday contains Web
attacks and Infiltration, and Friday contains Bot, DDoS, and PortScan.

## Preprocessing

Every pipeline converts infinities in `Flow Bytes/s` and `Flow Packets/s` to
missing values, adds non-finite indicators, and imputes medians learned from
training only. Logistic Regression additionally standardizes features using
training-fit statistics. Tree models do not scale features.

No preprocessing parameter is fit on validation or test. The seed is `42`.

## Threshold policy

For every trained model, validation thresholds must first satisfy
`ATTACK recall >= 0.80`; the qualifying threshold with the highest precision is
then frozen. Test is evaluated once after the pipeline, model configuration,
artifact hash, and threshold are frozen.

The attack score is not a calibrated real-world probability. A score has meaning
only relative to the corresponding frozen model and threshold.

## Final test results

| Evaluation | Model | Threshold | Precision | Recall | F1 | PR-AUC | False positives |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random | Logistic Regression | 0.885789 | 0.8621 | 0.7981 | 0.8289 | 0.9294 | 8,177 |
| Random | Random Forest | 0.999066 | 1.0000 | 0.7973 | 0.8872 | 0.9997 | 0 |
| Random | HGB | 0.997550 | 0.9999 | 0.8734 | 0.9324 | 0.9998 | 5 |
| Temporal | Logistic Regression | 0.056737 | 0.7355 | 0.8707 | 0.7974 | 0.8974 | 69,117 |
| Temporal | Random Forest | 0.207162 | 0.9500 | 0.4300 | 0.5920 | 0.9340 | 4,999 |
| Temporal | HGB | 0.811584 | 0.9921 | 0.0517 | 0.0984 | 0.8854 | 91 |

Random HGB has the strongest practical random-test tradeoff. It is not promoted
as a deployable model because the random evaluation does not measure later-day
generalization.

## Known failure modes

- Temporal HGB detects only 5.2% of Friday attacks at its frozen threshold.
- Temporal Random Forest detects 43.0% of Friday attacks and misses every Bot
  flow plus 98.0% of PortScan flows.
- Temporal Logistic Regression retains 87.1% recall but produces 69,117 false
  positives.
- The HGB median attack score falls from 0.9060 on Thursday to 0.0198 on Friday,
  demonstrating severe score and threshold instability.
- Random-test aggregate metrics hide weak family coverage, especially for Bot,
  PortScan, and extremely rare labels.
- CIC-IDS2017 is controlled 2017 traffic and cannot establish performance on
  current networks.

## Explainability

AI-09 uses deterministic validation-only permutation importance. Destination
Port dominates temporal importance for both tree models. This supports a
scenario-signature hypothesis but does not establish causality. Correlated
features can share or conceal importance, and global importance does not explain
an individual prediction.

## Ethical and security considerations

False negatives may create unwarranted confidence; false positives may waste
analyst time or trigger harmful automated responses. The models must not be used
to make autonomous blocking decisions. Uploaded demo data is processed locally,
but users remain responsible for ensuring that flow records contain no sensitive
or restricted information.

## Reproducibility

The release manifest records every included file, dataset checksum, learned
artifact hash, threshold, and final metric. Model binaries and raw data are not
committed. Reproduce them with the commands in `README.md`, then run:

```powershell
.\.venv\Scripts\python.exe scripts/build_release.py check --require-models
```

## License

No software or model license has been declared. Publication of release metadata
does not grant permission to copy, modify, or redistribute the work. A license
must be selected explicitly before presenting the project as open source.
