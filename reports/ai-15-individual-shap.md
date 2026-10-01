# AI-15 individual SHAP explanations

## Scope and frozen contract

AI-15 explains individual decisions from the frozen group-aware random HGB model.
It is descriptive post-test analysis: the model is not retrained, the threshold
is not changed, and SHAP values are not used for feature selection.

The product objective remains reliable `BENIGN` versus `ATTACK` detection. The
explanation objective is narrower: identify which transformed feature values
pushed nine already-frozen test decisions toward either class.

Three true positives, three false positives, and three false negatives are
selected deterministically. Within each category, the examples are the minimum,
median, and maximum attack scores. Labels and feature values are not inspected
before selection. This covers the score range but is not a representative sample
of every attack family or error pattern.

## Method

SHAP 0.52.0 `TreeExplainer` explains the HGB classifier's raw log-odds with
`tree_path_dependent` perturbation. The 71 explained inputs are the 69 prepared
features plus the two non-finite indicators created by the frozen preprocessing
pipeline.

For every row, the following identity is verified:

```text
sigmoid(base log-odds + sum(SHAP contributions)) = model attack score
```

The maximum absolute reconstruction error across the nine examples is
`4.41e-20`. Positive SHAP values push toward `ATTACK`; negative values push
toward `BENIGN`. Values are changes in log-odds, not percentage points or causal
effects.

## Selected decisions

The frozen threshold is `0.9975500791`.

| Category | Rank | Label | Attack score | Margin from threshold | Strongest ATTACK contribution | Strongest BENIGN contribution |
| --- | ---: | --- | ---: | ---: | --- | --- |
| True positive | Minimum | DoS Hulk | 0.997551 | +0.000001 | Init_Win_bytes_backward (+3.912) | Total Length of Fwd Packets (-0.268) |
| True positive | Median | DDoS | 0.999979 | +0.002429 | Bwd Packet Length Std (+9.374) | Bwd Header Length (-0.227) |
| True positive | Maximum | DoS Hulk | 0.999991 | +0.002441 | Bwd Packet Length Std (+8.846) | Bwd Header Length (-0.181) |
| False positive | Minimum | BENIGN | 0.997615 | +0.000065 | Destination Port (+3.052) | Bwd Packet Length Std (-0.489) |
| False positive | Median | BENIGN | 0.997781 | +0.000231 | Destination Port (+3.052) | Bwd Packet Length Std (-0.489) |
| False positive | Maximum | BENIGN | 0.998884 | +0.001334 | Destination Port (+2.768) | Bwd Packet Length Std (-0.445) |
| False negative | Minimum | PortScan | 0.000008 | -0.997542 | Max Packet Length (+0.097) | Init_Win_bytes_forward (-1.287) |
| False negative | Median | PortScan | 0.995952 | -0.001598 | Average Packet Size (+2.869) | Destination Port (-0.215) |
| False negative | Maximum | PortScan | 0.997550 | -0.000000 | Average Packet Size (+2.946) | Bwd Packet Length Std (-0.183) |

Rank means position within the category's score range, not importance or
representativeness.

## True positives

The two high-confidence DoS/DDoS examples are dominated by backward-packet and
overall packet-length variability, especially `Bwd Packet Length Std`. Port 80,
TCP window values, and packet-size dispersion provide additional positive
contributions. The minimum-score true positive is a boundary case only
`1.23e-6` above the threshold; its decision depends on several moderate signals
rather than the very large backward-packet variation found in the stronger
examples.

These explanations describe model logic, not proof that those features are
intrinsically malicious.

## False positives

All three selected benign errors have Destination Port 80 as their strongest
attack contribution. They also contain zero-valued backward packet size or
average-size patterns that interact with segment size, header length, and timing
features. Two nearly identical score-range examples come from Tuesday and
Wednesday, showing that the learned signature is not confined to one file.

The model appears to associate a particular port-80, low-payload flow shape with
attacks. This is consistent with the global importance result, but SHAP alone
cannot establish that the model learned a causal or universally invalid rule.

## False negatives

All three selected misses are PortScan flows from Friday's PortScan file. The
lowest-score miss receives strong benign pressure from
`Init_Win_bytes_forward = -1` and low/constant backward packet sizes. Its attack
evidence is weak, so the model places it near the benign extreme.

The median and maximum-score misses contain strong attack contributions from
small average/backward packet sizes, header length, and the forward TCP window.
They are rejected because the frozen threshold is exceptionally high. The
maximum miss is only `2.34e-7` below the decision boundary. This demonstrates
threshold sensitivity without justifying a post-test threshold change.

## Limitations

- SHAP explains the fitted model, not network causality or ground truth.
- Correlated features can redistribute contributions.
- Tree-path-dependent explanations use the fitted tree paths as their background
  distribution; they do not simulate a new operational environment.
- Nine deterministic examples provide inspectable evidence but do not estimate
  population-level frequencies.
- The random evaluation remains an optimistic within-dataset reference.
- Feature values are the post-imputation model inputs.

## Reproducibility record

- Evaluation: group-aware random test
- Model: Histogram Gradient Boosting
- Model artifact SHA-256:
  `1267d8ef0ba38e4ed336df4cca3863037a7f9c32c23c5be1f90a0d92120f498b`
- Frozen threshold: `0.9975500791153585`
- SHAP version: `0.52.0`
- Selection: minimum, median, and maximum score within TP, FP, and FN
- Machine-readable explanations: `reports/ai-15-individual-shap.json`
