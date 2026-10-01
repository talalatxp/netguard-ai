# AI-06 split design

## Objective and interpretation

The product objective is to classify completed network flows as `BENIGN` or
`ATTACK`. The experimental question is how a group-aware random reference
compares with evaluation on later capture days. CIC-IDS2017 attack families are
strongly separated by day, so the temporal result measures a combination of
later traffic, different scenarios, and attacks absent from training. A score
difference cannot be attributed to elapsed time alone.

## Frozen temporal assignment

| Partition | Capture days | CSV files | Raw rows | Raw attack rows |
| --- | --- | ---: | ---: | ---: |
| Train | Monday–Wednesday | 3 | 1,668,530 | 266,507 |
| Validation | Thursday | 2 | 458,968 | 2,216 |
| Test | Friday | 3 | 703,245 | 288,923 |

These are counts **before** the agreed global exact full-row deduplication.
Prepared-data counts must be recalculated and recorded. The eight CSV filenames
identify their day and, for some files, morning or afternoon. They do not
contain a row-level timestamp. All files from the same day stay in the same
partition. For deterministic deduplication, compare days explicitly in
Monday-to-Friday order; a stable file-and-row tie-breaker within a day must not
be described as a verified within-day timestamp order.

The training attacks are FTP-Patator, SSH-Patator, the four Wednesday DoS
families, and Heartbleed. Validation contains Infiltration and three Web Attack
labels; test contains Bot, DDoS, and PortScan. Every attack label in validation
and test is absent from training. This is an unusually hard test of unseen
attack families, not an estimate of performance on later examples of the same
attack families. Heartbleed (11 raw rows) and Infiltration (36 raw rows) are too
rare for reliable per-label conclusions.

## Evaluation safeguards

1. Preserve the raw CSVs. Apply the already agreed full-row deduplication once,
   before either split design, retaining the earliest day and a deterministic
   within-day tie-breaker. Record removals by day and original label.
2. Assign temporal partitions by day, never by lexicographically sorted path.
   Fit preprocessing and models on training data only. Use validation labels
   for configuration and the decision threshold; do not use test labels for
   either purpose.
3. Keep feature-hash groups intact across the random reference partitions.
   Use random seed `42` and target row fractions 70% train, 15% validation,
   and 15% test. Record actual row/class fractions and assert zero shared
   feature hashes across its partitions. The seed has no special scientific
   meaning; it makes the assignment reproducible.
4. For the temporal split, report shared feature hashes rather than moving rows
   between days. Report metrics on all retained later rows and separately on
   validation hashes absent from train and test hashes absent from both earlier
   partitions. Keep conflicting-label groups and report their impact.
5. Select the threshold on validation by requiring `ATTACK` recall at least
   0.80 before maximizing precision. If no candidate qualifies, report that
   constraint as unmet; do not inspect test results to relax it.
6. Freeze preprocessing, model, threshold, and reporting rules before the final
   test evaluation. Test is evaluated once for the final estimate.

The design has been implemented. Generated counts, overlap checks, and manifest
metadata are recorded in `split-summary.json` and `split-summary.md`. The local
manifest is reproducible from the verified raw files and is not committed.
