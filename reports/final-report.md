# NetGuard AI final research report

## Abstract

NetGuard AI evaluates binary network-intrusion classification on CIC-IDS2017
under a group-aware random split and a strict day-based temporal split. The
project asks whether strong within-dataset results survive later traffic with
attack families absent from training. They do not. HGB reaches random-test
precision 0.9999 and recall 0.8734, but its frozen temporal threshold detects
only 0.0517 of Friday attacks. The result demonstrates why leakage controls,
chronological evaluation, absolute false-positive counts, and attack-family
coverage matter more than a single headline metric.

## Objective and research question

The product objective is to identify `ATTACK` flows while maintaining an
operationally useful false-positive rate. The experimental question is whether a
supervised classifier trained on CIC-IDS2017 generalizes from earlier to later
traffic, rather than merely recognizing patterns redistributed within one
dataset snapshot.

These are deliberately separate. A model may answer the experimental question
poorly even when it obtains excellent random-split results.

## Dataset and integrity

The official `MachineLearningCSV.zip` archive contains eight labelled CSV files,
2,830,743 rows, 78 feature columns plus `Label`, 2,273,097 benign flows, and
557,646 attacks across 14 raw attack labels. The archive, filename, timestamp,
size, and SHA-256 inventory are recorded before processing.

The quality audit found non-finite rate values, constant features, a duplicated
`Fwd Header Length` column, exact duplicate rows, repeated feature vectors, rare
labels, and some identical feature vectors with conflicting labels. The pipeline
removes exact duplicate rows deterministically but preserves conflicting labels.
After preparation, 2,522,362 rows and 69 numeric features remain.

## Leakage controls and evaluation

The random reference assigns every identical `feature_hash` group to one
partition using a stable SHA-256-derived value from seed `42` and the feature
hash. No feature-hash group crosses random train, validation, and test.

The temporal evaluation uses:

- Monday-Wednesday for training;
- Thursday for validation;
- Friday for final test.

Preprocessing and models are fit on training only. Validation selects model
configuration and threshold. Threshold candidates must meet attack recall 0.80
before precision is maximized. Test is used once after choices and artifact
hashes are frozen.

## Models

The experiment compares a class-prior dummy reference, averaged SGD Logistic
Regression, a resource-aware Random Forest, and HGB. Logistic Regression uses
median imputation and standardization. Tree models use median imputation without
scaling. All learned pipelines include explicit handling of non-finite rate
features.

## Final results

| Evaluation | Model | Precision | Recall | F1 | PR-AUC | False positives |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Random | Logistic Regression | 0.8621 | 0.7981 | 0.8289 | 0.9294 | 8,177 |
| Random | Random Forest | 1.0000 | 0.7973 | 0.8872 | 0.9997 | 0 |
| Random | HGB | 0.9999 | 0.8734 | 0.9324 | 0.9998 | 5 |
| Temporal | Logistic Regression | 0.7355 | 0.8707 | 0.7974 | 0.8974 | 69,117 |
| Temporal | Random Forest | 0.9500 | 0.4300 | 0.5920 | 0.9340 | 4,999 |
| Temporal | HGB | 0.9921 | 0.0517 | 0.0984 | 0.8854 | 91 |

Random HGB is the strongest within-dataset model. Temporal evaluation reverses
the apparent conclusion. Logistic Regression remains sensitive but generates too
many false alarms. Random Forest reduces false positives but misses most
PortScan traffic and every Bot flow. HGB is extremely conservative and misses
almost 95% of Friday attacks.

## Error analysis

HGB's median attack score is 0.9060 on Thursday but 0.0198 on Friday, far below
its frozen threshold of 0.8116. Friday recall is 0 for Bot, 0.0868 for DDoS, and
0.0034 for PortScan. Its Friday PR-AUC of 0.8854 shows that ranking signal remains,
but the validation-selected absolute score scale does not transfer.

Validation permutation importance places Destination Port first for both
temporal tree models. This is consistent with reliance on service or scenario
signatures that change across days and families. The analysis is correlational,
and no test-driven threshold or feature revision is made.

Individual SHAP explanations for random HGB cover the minimum, median, and
maximum scores among true positives, false positives, and false negatives. The
three selected benign errors are pushed toward attack by a port-80, low-payload
signature. All three selected misses are PortScan; two contain strong attack
evidence but remain just below the frozen threshold. SHAP additivity is verified
against the model score and is not interpreted causally.

## Demonstration

The local Streamlit application loads one of six frozen learned configurations,
verifies its artifact hash, validates a 69-feature CSV, displays the attack score
and frozen threshold, and returns a downloadable decision table. It does not
capture packets, retrain models, or represent scores as calibrated real-world
probabilities.

## Conclusion

The principal result is not a production classifier. It is evidence that
near-perfect random performance can coexist with severe temporal failure.
Reproducible hashes, group isolation, chronological partitions, frozen
thresholds, attack-family breakdowns, and absolute false-positive counts expose
limitations that aggregate random metrics conceal.

No evaluated configuration satisfies the product objective on later unseen
traffic. Any improvement requires a new experimental cycle and new evaluation
data, not adjustment against the frozen Friday test.

## Limitations and future work

- CIC-IDS2017 is old, controlled, and scenario-specific.
- Day and attack-family shift occur together, so their effects are not fully
  separable.
- Several labels are too rare for stable family-level estimates.
- Feature importance is global and affected by correlated variables.
- Scores are not calibrated across days.
- A future experiment should use multiple chronological validation periods,
  current datasets, explicit calibration monitoring, and a new untouched test.

## Reproducibility

Release `0.2.0` includes the source, tests, reports, model card, exact dependency
versions, and a machine-readable integrity manifest. Raw data and model binaries
remain external; their required SHA-256 values are included in that manifest.
The deterministic source ZIP can be rebuilt with `scripts/build_release.py`.
