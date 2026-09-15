# AI-06 split build results

## Prepared population

The split builder scanned the verified eight-file CIC-IDS2017 snapshot in the
explicit order recorded in `split-design.md`. It retained the first occurrence
of each exact full CSV row and wrote a local row-reference manifest. It did not
impute, scale, resample, or fit any learned transformation.

| Measure | Result |
| --- | ---: |
| Raw rows | 2,830,743 |
| Retained rows | 2,522,362 |
| Exact duplicate rows removed | 308,381 |
| Planned numeric features | 69 |
| Retained conflicting binary-target groups | 698 |
| Rows in those groups | 1,396 |

The removed-row total and per-label counts match the AI-04 audit. The raw files
remain unchanged. Web Attack labels are normalized into separate canonical
labels while the source label is preserved in the manifest. An unknown label,
malformed row, schema mismatch, or mismatch between the duplicate
`Fwd Header Length` columns stops the build.

## Random reference

| Partition | Rows | Share | Benign | Attack | Attack rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 1,765,722 | 70.00% | 1,467,822 | 297,900 | 16.87% |
| Validation | 377,894 | 14.98% | 313,978 | 63,916 | 16.91% |
| Test | 378,746 | 15.02% | 314,684 | 64,062 | 16.91% |

Assignment uses seed `42` and exact prepared-feature hashes. The generated
split has zero feature-hash groups shared across random partitions. Hash-based
assignment produces the target proportions without depending on input order or
Python's process-randomized `hash()` function.

## Temporal evaluation

| Partition | Days | Rows | Benign | Attack | Attack rate |
| --- | --- | ---: | ---: | ---: | ---: |
| Train | Monday–Wednesday | 1,527,339 | 1,324,428 | 202,911 | 13.29% |
| Validation | Thursday | 398,717 | 396,538 | 2,179 | 0.55% |
| Test | Friday | 596,306 | 375,518 | 220,788 | 37.03% |

Validation contains 41 retained rows whose exact prepared-feature hash appears
in training. Test contains 581 retained rows whose hash appears in train or
validation. These rows remain in the primary temporal evaluation because days
are not rearranged. The separate novel-vector subsets contain 398,676 validation
rows and 595,725 test rows.

All attack families in validation and test are absent from training. Temporal
results therefore measure a combination of later traffic, different scenarios,
and unseen attack families; they do not isolate elapsed time.

## Manifest

The generated `data/processed/split-manifest.csv` contains 2,522,362 data rows
plus one header row. Each record stores the original file and one-based line,
raw and canonical labels, binary target, prepared-feature SHA-256, random and
temporal partitions, and temporal-novel flag. It does not duplicate the feature
values.

| Property | Value |
| --- | --- |
| Size | 485,056,985 bytes |
| SHA-256 | `723bfe0fa18f012b0d8e55a699b53394da5001e83dc85efa5ab34ca883025cbd` |
| Git policy | Local generated artifact; ignored |

The versioned `split-summary.json` is the machine-readable record of the build,
including per-file and per-label counts, feature names, configuration, manifest
metadata, and overlap checks.
