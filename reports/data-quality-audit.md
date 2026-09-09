# CIC-IDS2017 data-quality audit

## Status

The audit is complete for the verified eight-file `MachineLearningCSV.zip`
snapshot. The cleaning policy below is proposed and must be frozen before the
final data partitions and preprocessing pipeline are created.

## Method

`scripts/audit_dataset.py` scans every CSV row without loading the full dataset
into a dataframe. It:

- parses every cell with Python's numeric parser;
- counts empty, `NaN`, positive-infinity, and negative-infinity values;
- fingerprints each raw row with SHA-256 after removing only its line ending;
- reports duplicate rows within and across files;
- compares columns whose normalized names collide.

Run the audit with:

```powershell
python scripts/audit_dataset.py "data/raw/MachineLearningCSV/**/*.csv" --output reports/data-quality-audit.json
```

## Findings

### Schema and types

| Finding | Result |
| --- | ---: |
| Rows scanned | 2,830,743 |
| Feature columns inferred as numeric | 78 |
| String columns | 1 (`Label`) |
| Empty cells | 0 |
| Structurally malformed rows | 0 |

Leading and trailing whitespace is present in many raw column names. After
trimming that whitespace, `Fwd Header Length` appears twice, at zero-based
indices 34 and 55. The two columns have zero mismatches across the complete
dataset and are therefore redundant.

### Non-finite values

| Column | `NaN` | `+Infinity` | `-Infinity` |
| --- | ---: | ---: | ---: |
| `Flow Bytes/s` | 1,358 | 1,509 | 0 |
| `Flow Packets/s` | 0 | 2,867 | 0 |
| **Total cells** | **1,358** | **4,376** | **0** |

The 5,734 non-finite cells occur in 2,867 rows, approximately 0.10% of the
dataset. Their concentration in rate features is consistent with division by a
zero-duration flow, so these rows may represent a systematic flow condition
rather than random missingness.

### Exact duplicates

| Finding | Result |
| --- | ---: |
| Unique well-formed rows | 2,522,362 |
| Duplicate rows | 308,381 |
| Duplicate rate | 10.894% |
| Duplicate `BENIGN` rows | 176,613 |
| Duplicate attack rows | 131,768 |

The largest duplicate groups by label are:

| Label | Duplicate rows |
| --- | ---: |
| `BENIGN` | 176,613 |
| `PortScan` | 68,111 |
| `DoS Hulk` | 58,224 |
| `SSH-Patator` | 2,678 |
| `FTP-Patator` | 2,005 |

Duplicates occur both within individual files and across different files. If
duplicates cross partitions, a random evaluation can measure recognition of an
already observed row rather than generalization.

### Labels

The raw labels contain 14 attack values plus `BENIGN`. Three `Web Attack`
values contain the Unicode replacement character (`�`) in the verified source
files. The raw label must be retained for traceability, while a separate
normalized label can use stable ASCII names.

## Proposed cleaning policy

1. Preserve every file under `data/raw/` unchanged.
2. Trim column-name whitespace and convert names to one consistent convention.
3. Remove the second `Fwd Header Length` column after asserting that both raw
   copies are still identical.
4. Preserve the exact source label as `original_attack_label`; create a separate
   normalized label and derive the binary target as `BENIGN` or `ATTACK`.
5. Remove exact duplicate rows before either evaluation. Process days in
   chronological order and retain the earliest occurrence, preventing a later
   duplicate from leaking an earlier observation across a temporal boundary.
6. Convert positive and negative infinity to missing values. Add missing-value
   indicators for the affected rate features, then median-impute using parameters
   fitted on the training partition only.
7. Record rows removed, values transformed, and counts by original label for
   every generated dataset.

The non-finite policy retains the affected flows because deleting them could
systematically remove zero-duration traffic. The indicators preserve the fact
that the original rate was undefined, while train-only median imputation allows
models that require finite numeric inputs to operate without leaking validation
or test statistics.

## Remaining limitations

- SHA-256 duplicate fingerprints make collisions negligibly unlikely, but the
  audit does not group near-duplicate flows.
- Type inference establishes numeric parseability, not the semantic unit or
  valid domain of each feature.
- A later leakage audit must still examine identifiers, scenario proxies,
  timestamps, and features that reveal the capture day or attack setup.
