# Feature-vector repetition and label-conflict audit

## Scope

This is the first control in AI-05, not the complete leakage audit. It checks
whether rows have exactly the same feature-cell strings after excluding `Label`
and the redundant second `Fwd Header Length` column. It does not perform a
train/validation/test split, numeric canonicalization, or near-duplicate search.

Run it with:

```powershell
python scripts/audit_feature_leakage.py "data/raw/MachineLearningCSV/**/*.csv" --output reports/feature-leakage-audit.json --groups-output reports/feature-leakage-groups.jsonl
```

The JSON summary is committed. The complete 65 MB JSONL group listing is
reproducible locally and ignored by Git. Every repeated group records its SHA-256
feature hash, row count, original-label counts, original CSV file and one-based
line number for every occurrence, and whether it spans files. The summary keeps
five examples of each category.

## Results

| Measure | Result |
| --- | ---: |
| Well-formed rows scanned | 2,830,743 |
| Repeated feature-vector groups | 95,479 |
| Rows in repeated groups | 404,558 |
| Same-label groups | 94,781 |
| Rows in same-label groups | 397,538 |
| Conflicting-label groups | 698 |
| Rows in conflicting-label groups | 7,020 |
| Repeated groups spanning multiple files | 34,208 |

Of the 698 conflicting-label groups, 564 combine `BENIGN` with `PortScan`,
130 combine `BENIGN` with `DoS Hulk`, three combine `BENIGN` with `DDoS`,
and one combines `BENIGN` with `DoS slowloris`. 664 conflicting groups span
multiple files.

These are **feature-vector groups**, not the raw-row duplicate count from the
data-quality audit. Raw-row duplicates require an identical complete CSV row,
including `Label`; this audit intentionally omits `Label` to expose cases where
the model sees the same inputs with different answers.

## Interpretation and remaining checks

A repeated vector could represent a repeated recording or distinct flows with
identical measured values. A conflicting label could reflect ambiguous features,
different underlying flows, or labeling errors. The audit does not decide which
explanation applies, and it does not remove or relabel any row.

`cross_file` means only that occurrences are in different CSV files. It does not
establish chronological order or prove that a particular future split leaks.
The next controls must define the partitions, verify that identical feature
vectors do not cross them under the chosen policy, and check that preprocessing
parameters are fitted only on training data.

## Frozen evaluation policy for repeated vectors

1. Apply the already agreed exact **full-row** deduplication before either
   evaluation, retaining the earliest occurrence in explicit day order. This
   preparation step is not implemented by this audit.
2. Make the random reference group-aware by `feature_hash`: all remaining rows
   with the same observable feature vector belong to one partition. Use a fixed
   seed and check the resulting class balance; conflicting-label groups cannot
   be perfectly stratified by a single label.
3. Keep the temporal partitions in day order. Do not move a later row to an
   earlier partition merely because its feature hash appeared before. The
   primary temporal result uses **all later rows remaining after full-row
   deduplication**, including repeated feature vectors.
4. Separately report temporal results on novel vectors: validation hashes absent
   from training, and test hashes absent from both training and validation.
   Report the row and label counts for the full and novel subsets so the
   comparison is interpretable.
5. Preserve conflicting-label rows and report their counts and error rates;
   do not silently relabel or delete them. Freeze model and threshold decisions
   before evaluating the final test set.

For the random reference, a nonzero shared-hash count between partitions is an
error. For the temporal evaluation, shared hashes are measured and reported,
not treated as an automatic failure. These decisions distinguish performance
on later traffic from performance on feature patterns not observed in earlier
partitions. The hash compares exact CSV strings only; transformed numeric
equivalence and near-duplicate scenarios still require later checks.

## Direct target and metadata leakage check

The verified CSV schema has 78 numeric columns and one string `Label` column.
It has no `Timestamp`, `Flow ID`, source-IP, or destination-IP column. Removing
the redundant header-length copy and eight constant numeric columns leaves
69 planned numeric model features before missing-value indicators are added.

`Label`, the canonical label, and the derived binary target are **targets or
audit metadata**, never model inputs. File path, capture day, and CSV line
number may be retained for split assignment and traceability but must also be
excluded from the model matrix. A future pipeline should assert these
exclusions and unique feature names rather than relying on manual selection.

`Destination Port` is available from a completed flow and remains a candidate
feature; it is not automatically target leakage. It may be a scenario shortcut,
so feature-importance and ablation analyses should later measure dependence on
it. The intended prediction point is after a flow's summary has been computed;
this audit does not establish real-time, before-flow-completion availability.
