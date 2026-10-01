# AI-07 preprocessing and baseline results

## Scope

The product objective is to classify completed network flows as `BENIGN` or
`ATTACK` while controlling false alarms. This block compares a group-aware
random reference with a later-day temporal evaluation. The temporal result also
measures generalization to attack families absent from training; it does not
isolate elapsed time.

AI-07 materializes one local `float32` feature matrix aligned with the frozen
split manifest. Before conversion, every retained source row is rechecked for
schema, duplicate `Fwd Header Length` equality, label, target, and feature hash.
The generated matrix has 2,522,362 rows and 69 numeric input features. It is
ignored by Git and can be rebuilt from the verified raw files.

## Leakage-safe preprocessing

Each evaluation owns an independently fitted pipeline:

1. Replace positive and negative infinity with missing values and add explicit
   indicators for `Flow Bytes/s` and `Flow Packets/s`.
2. Learn median imputations from that evaluation's training partition only.
3. Learn standardization parameters from that training partition only.
4. Fit the classifier on the transformed training partition.
5. Apply the frozen pipeline to validation and test without refitting.

The learned baseline is linear logistic regression optimized with stochastic
gradient descent. Its fixed configuration uses L2 regularization, balanced
class weights, seed `42`, and averaged coefficients. `DummyClassifier` with the
training prior is the trivial reference.

## Frozen validation decisions

Threshold candidates first had to achieve `ATTACK recall >= 0.80` on validation.
The qualifying threshold with the highest `ATTACK` precision was frozen. Model
configuration, preprocessing, artifacts, and thresholds were recorded before
test was accessed.

| Evaluation | Model | Threshold | Precision | Recall | F1 | PR-AUC | False positives | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random validation | Dummy | 0.168713 | 0.1691 | 1.0000 | 0.2893 | 0.1691 | 313,978 | 1.0000 |
| Random validation | Logistic | 0.885789 | 0.8631 | 0.8011 | 0.8309 | 0.9299 | 8,120 | 0.0259 |
| Temporal validation | Dummy | 0.132853 | 0.0055 | 1.0000 | 0.0109 | 0.0055 | 396,538 | 1.0000 |
| Temporal validation | Logistic | 0.056737 | 0.0207 | 0.9257 | 0.0404 | 0.0106 | 95,643 | 0.2412 |

All 2,179 temporal validation attacks belong to families absent from temporal
training. The logistic threshold satisfies the recall constraint, but its
precision and false-positive count make the validation result operationally
unusable.

## Final test results

Test was evaluated once after the validation record and four model artifacts
were frozen.

| Evaluation | Model | Precision | Recall | F1 | PR-AUC | False positives | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random test | Dummy | 0.1691 | 1.0000 | 0.2893 | 0.1691 | 314,684 | 1.0000 |
| Random test | Logistic | 0.8621 | 0.7981 | 0.8289 | 0.9294 | 8,177 | 0.0260 |
| Temporal test | Dummy | 0.3703 | 1.0000 | 0.5404 | 0.3703 | 375,518 | 1.0000 |
| Temporal test | Logistic | 0.7355 | 0.8707 | 0.7974 | 0.8974 | 69,117 | 0.1841 |

The random test closely matches random validation. Its recall is slightly below
0.80 because the constraint was enforced on validation, not guaranteed on test.

All 220,788 temporal test attacks are from Bot, DDoS, or PortScan, which were
absent from temporal training. On the subset whose exact feature vectors were
also absent from earlier partitions, the logistic model has precision 0.7352,
recall 0.8710, F1 0.7974, PR-AUC 0.8975, and 69,102 false positives. The strong
test result does not repair the very poor temporal validation result: Thursday
and Friday contain different attack families and very different attack rates.
The 18.4% test false-positive rate is still unsuitable for operational use.

## Reproducibility record

- Validation record SHA-256 before test:
  `a1595380729246f225c436999e0c372509d09aeb66d241e5f61fa0da94df9b6a`
- Model-matrix metadata SHA-256:
  `020ff9cb62e41b849250664d57ad5e258b5ae91118c3705698874ce3b0c87529`
- Split manifest SHA-256:
  `723bfe0fa18f012b0d8e55a699b53394da5001e83dc85efa5ab34ca883025cbd`
- Full machine-readable validation decisions:
  `reports/ai-07-validation.json`
- Full machine-readable final results:
  `reports/ai-07-baseline-results.json`

The local model artifacts are intentionally ignored by Git. Their individual
SHA-256 hashes are recorded in both JSON reports.

## Interpretation

The random reference demonstrates that the learned linear baseline captures
repeatable structure when every attack family and capture scenario is mixed
across partitions. The temporal experiment is less stable: validation and test
contain different unseen attack families and substantially different class
prevalence. These results are evidence about this frozen CIC-IDS2017 protocol,
not a probability that the model will detect modern or real-world attacks.
