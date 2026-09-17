# AI-09 error, coverage, and feature-importance analysis

## Scope and analysis contract

AI-09 explains the frozen AI-07 and AI-08 results. It does not train a model,
change a threshold, select features, or create a new performance estimate. Any
future model change suggested by this analysis must be evaluated as a new
experiment with a new untouched test set or protocol.

The product objective remains binary `BENIGN` versus `ATTACK` detection with a
useful false-positive rate. The experimental question is why performance from
the group-aware random evaluation does not transfer consistently to later days
and attack families.

The analysis recomputes scores from the hashed frozen Logistic Regression,
Random Forest, and histogram gradient-boosting (HGB) artifacts. It verifies all
overall metrics against the committed final reports before producing breakdowns
by attack label and source file. Feature importance uses three deterministic
permutations per raw feature and measures PR-AUC loss on balanced validation
samples only. Test data is never used to rank or select features.

## Central temporal finding

The HGB model's Thursday attack-score median is 0.9060, above its frozen
threshold of 0.8116. On Friday, the attack-score median falls to 0.0198. The
model still ranks many attacks above benign traffic (`PR-AUC = 0.8854`), but its
absolute score scale does not transfer to the new day and families.

| Temporal model | Thursday attack median | Friday attack median | Thursday recall | Friday recall | Friday false positives |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.0575 | 0.6499 | 0.9257 | 0.8707 | 69,117 |
| Random Forest | 0.2323 | 0.1695 | 0.8821 | 0.4300 | 4,999 |
| HGB | 0.9060 | 0.0198 | 0.8146 | 0.0517 | 91 |

This is a threshold-calibration and scenario-shift failure, not an absence of
all ranking signal. Replacing the threshold after seeing Friday would convert
the test set into validation data and is deliberately not done.

## Temporal attack-family coverage

Thursday validation contains Web attacks and Infiltration, all absent from the
Monday-Wednesday training period. Friday test contains another three unseen
families: Bot, DDoS, and PortScan.

| Partition | Attack family | Rows | Logistic recall | Random Forest recall | HGB recall | HGB median score |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Thursday validation | Infiltration | 36 | 0.2778 | 0.0000 | 0.0000 | 0.000007 |
| Thursday validation | Web Brute Force | 1,470 | 0.9231 | 0.8871 | 0.8061 | 0.9060 |
| Thursday validation | Web SQL Injection | 21 | 0.8571 | 0.6667 | 0.4762 | 0.6497 |
| Thursday validation | Web XSS | 652 | 0.9693 | 0.9264 | 0.8896 | 0.9166 |
| Friday test | Bot | 1,953 | 0.2734 | 0.0000 | 0.0000 | 0.000006 |
| Friday test | DDoS | 128,016 | 0.9995 | 0.7275 | 0.0868 | 0.4648 |
| Friday test | PortScan | 90,819 | 0.7019 | 0.0200 | 0.0034 | 0.000007 |

No tree model detects a Bot flow at its frozen temporal threshold. Random Forest
retains useful DDoS recall but almost completely misses PortScan. HGB rejects
most DDoS flows and almost every Bot and PortScan flow. Logistic Regression
transfers recall better, especially for DDoS, but generates 69,117 Friday false
positives and therefore does not meet the product objective.

## Errors by source file

| Model | Friday source file | False positives | False negatives | Attack recall |
| --- | --- | ---: | ---: | ---: |
| Logistic Regression | Morning / Bot | 33,255 | 1,419 | 0.2734 |
| Logistic Regression | PortScan | 21,899 | 27,073 | 0.7019 |
| Logistic Regression | DDoS | 13,963 | 61 | 0.9995 |
| Random Forest | Morning / Bot | 583 | 1,953 | 0.0000 |
| Random Forest | PortScan | 433 | 89,007 | 0.0200 |
| Random Forest | DDoS | 3,983 | 34,885 | 0.7275 |
| HGB | Morning / Bot | 50 | 1,953 | 0.0000 |
| HGB | PortScan | 23 | 90,511 | 0.0034 |
| HGB | DDoS | 18 | 116,899 | 0.0868 |

The false-positive/false-negative tradeoff is model-specific. Logistic
Regression is sensitive but operationally noisy. HGB is extremely conservative
on Friday. Random Forest lies between them but still misses 125,845 of 220,788
Friday attacks.

## Random-split coverage is not uniform

HGB is the strongest practical random-test model (`precision = 0.9999`,
`recall = 0.8734`, `F1 = 0.9324`), but the aggregate result hides large
family differences. It detects 99.7% of DDoS and 98.1% of DoS Hulk, while
detecting 50.6% of PortScan, 32.5% of Bot, and none of the two Heartbleed or five
Infiltration rows. Very small family counts make the last estimates unstable,
but the PortScan and Bot gaps are supported by hundreds or thousands of rows.

Random Forest's perfect random-test precision is also threshold-dependent. Its
0.999066 threshold produces zero false positives but detects only 48.5% of
PortScan, 45.3% of DoS GoldenEye, 14.1% of DoS Slowhttptest, and 12.2% of Bot.

## Validation permutation importance

Permutation importance measures association with validation ranking, not
causality. Correlated features may share or hide importance, and magnitudes are
affected by each model's baseline performance.

| Evaluation | Model | Most important validation features (mean PR-AUC drop) |
| --- | --- | --- |
| Random | Logistic Regression | Packet Length Variance (0.4479), Idle Max (0.0824), PSH Flag Count (0.0541) |
| Random | Random Forest | Destination Port (0.00156), Init_Win_bytes_backward (0.00023), Avg Bwd Segment Size (0.00021) |
| Random | HGB | Bwd Packet Length Std (0.00539), Destination Port (0.00478), Init_Win_bytes_forward (0.00086) |
| Temporal | Logistic Regression | Bwd Packet Length Min (0.1838), Destination Port (0.1089), Fwd Packet Length Std (0.0498) |
| Temporal | Random Forest | Destination Port (0.2283), Fwd IAT Min (0.0184), Min Packet Length (0.0125) |
| Temporal | HGB | Destination Port (0.1395), Init_Win_bytes_forward (0.00871), Bwd Packet Length Mean (0.00474) |

Destination Port is the dominant temporal feature for both tree models and the
second feature for Logistic Regression. This supports, but does not prove, the
hypothesis that the models learned service/scenario signatures that changed
between Thursday Web attacks and Friday Bot, DDoS, and PortScan traffic.

## Decision and next experiment

AI-09 does not promote a deployable model. Random HGB is an optimistic reference;
temporal HGB is too insensitive on Friday; temporal Logistic Regression is too
noisy. The next model iteration should be a new experiment, not a revision of
these test results. Candidate questions include validation across multiple days,
threshold calibration robust to day shift, and training coverage that separates
attack-family generalization from time generalization.

AI-10 may build a local explanatory demo only if it clearly labels predictions
as experimental and does not imply production intrusion-detection capability.

## Reproducibility record

- Seed: `42`
- Matrix metadata SHA-256:
  `2b9c2a5631dc0ddd84ececf919c0935a8eb52aa76d90ddf40da7ed84b8b2cea0`
- Feature-array SHA-256:
  `e79c95118af3e47ae0f4f011460024a1e39cc07490625740a70552bf7798a1c7`
- The analyzer verifies all seven frozen array hashes. It does not require the
  generated metadata timestamp to be identical.
- AI-07 final results SHA-256:
  `3a80bd5c7c72d50b1c58258e39b0519084a0f0173c3d3716ce1202d3b24d90c9`
- AI-08 final results SHA-256:
  `8554330f5f9f34774c3482ab6796e7327d1912edbb927421b23fbc09058653ae`
- Machine-readable analysis: `reports/ai-09-error-analysis.json`
- No row-level scores or raw data are committed.
