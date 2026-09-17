# AI-08 tree-model comparison

## Scope

AI-08 compares Random Forest and histogram-based gradient boosting (HGB) with
the logistic-regression baseline from AI-07. The product objective remains
binary flow classification as `BENIGN` or `ATTACK`. The experimental question
is whether nonlinear tree models improve both the group-aware random reference
and generalization to later days containing attack families absent from
training.

The tree models use the same deterministic non-finite conversion, missing-value
indicators, and train-only median imputation as AI-07. They do not use feature
scaling because tree splits depend on feature ordering rather than scale. Each
evaluation owns an independently fitted pipeline.

## Frozen configurations

Random Forest was constrained for the available memory: 80 trees, maximum depth
18, minimum leaf size 20, `sqrt` feature sampling, balanced bootstrap weights,
and 35% of training rows per tree. HGB used 150 maximum iterations, learning
rate 0.08, 31 leaf nodes, minimum leaf size 50, L2 regularization 1.0, balanced
class weights, and early stopping using 10% of train only.

No hyperparameter search was performed. These settings were fixed before
validation. Each model selected its threshold by first requiring validation
`ATTACK recall >= 0.80` and then maximizing precision. The formal validation
winner maximized precision, followed by PR-AUC and F1 as tie-breakers. Test was
evaluated once after model artifacts, thresholds, and winners were frozen.

## Validation comparison

| Evaluation | Model | Threshold | Precision | Recall | F1 | PR-AUC | False positives | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random | Logistic regression | 0.885789 | 0.8631 | 0.8011 | 0.8309 | 0.9299 | 8,120 | 0.0259 |
| Random | Random Forest | 0.999066 | 1.0000 | 0.8000 | 0.8889 | 0.9998 | 0 | 0.0000 |
| Random | HGB | 0.997550 | 1.0000 | 0.8726 | 0.9319 | 0.9999 | 1 | 0.000003 |
| Temporal | Logistic regression | 0.056737 | 0.0207 | 0.9257 | 0.0404 | 0.0106 | 95,643 | 0.2412 |
| Temporal | Random Forest | 0.207162 | 0.4840 | 0.8821 | 0.6250 | 0.3260 | 2,049 | 0.0052 |
| Temporal | HGB | 0.811584 | 0.9367 | 0.8146 | 0.8714 | 0.8579 | 120 | 0.0003 |

Random Forest is the formal random-validation winner because its selected
threshold has precision exactly 1.0. HGB is the temporal-validation winner.
HGB also provides the stronger random-validation recall/F1 tradeoff despite one
false positive.

All temporal validation attacks are from families absent from temporal train.
On feature vectors also absent from train, HGB records precision 0.9543, recall
0.8146, F1 0.8789, PR-AUC 0.8869, and 85 false positives.

## Final test comparison

| Evaluation | Model | Precision | Recall | F1 | PR-AUC | False positives | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random | Logistic regression | 0.8621 | 0.7981 | 0.8289 | 0.9294 | 8,177 | 0.0260 |
| Random | Random Forest | 1.0000 | 0.7973 | 0.8872 | 0.9997 | 0 | 0.0000 |
| Random | HGB | 0.9999 | 0.8734 | 0.9324 | 0.9998 | 5 | 0.00002 |
| Temporal | Logistic regression | 0.7355 | 0.8707 | 0.7974 | 0.8974 | 69,117 | 0.1841 |
| Temporal | Random Forest | 0.9500 | 0.4300 | 0.5920 | 0.9340 | 4,999 | 0.0133 |
| Temporal | HGB | 0.9921 | 0.0517 | 0.0984 | 0.8854 | 91 | 0.0002 |

The random results are stable between validation and test. HGB gives the best
random test F1 and recall while retaining almost perfect precision.

The temporal thresholds do not transfer consistently across unseen attack
families. HGB, selected on Thursday, detects only 5.2% of Friday attacks at its
frozen threshold. Random Forest detects 43.0%. Their high temporal test PR-AUC
shows that probability rankings still contain signal, but changing the
threshold after observing test would violate the protocol. Logistic regression
has higher temporal test recall but 69,117 false positives.

All 220,788 temporal test attacks are Bot, DDoS, or PortScan and are absent from
temporal training. Results on exact feature vectors absent from earlier days are
nearly identical: Random Forest recall 0.4311 with 4,984 false positives, and
HGB recall 0.0519 with 78 false positives.

## Interpretation

Tree models substantially improve the random reference and Thursday temporal
validation. They do not establish stable temporal generalization. The large
validation-to-test recall collapse, especially for HGB, is evidence of attack-
family and scenario shift plus threshold-calibration instability. It must not
be hidden by choosing a new test threshold.

AI-09 should analyze errors by day and attack label, inspect score
distributions, compare feature importance, and investigate why Thursday's
threshold rejects most Friday attacks.

## Reproducibility record

- AI-08 validation record SHA-256 before test:
  `16bb46c27ba9b00dd69755f566de0c1e7eef236d89973d786157718b7b00eeb7`
- AI-08 model-matrix metadata SHA-256:
  `2b9c2a5631dc0ddd84ececf919c0935a8eb52aa76d90ddf40da7ed84b8b2cea0`
- Feature-array SHA-256, identical to AI-07:
  `e79c95118af3e47ae0f4f011460024a1e39cc07490625740a70552bf7798a1c7`
- Full frozen validation record: `reports/ai-08-validation.json`
- Full final results: `reports/ai-08-model-comparison-results.json`

Model artifacts remain local and ignored by Git. Their hashes and fit durations
are recorded in the machine-readable reports.
