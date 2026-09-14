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
