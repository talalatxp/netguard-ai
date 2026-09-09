# CIC-IDS2017 initial data profile

## Interpretation

The initial profile confirms that the verified CIC-IDS2017 distribution contains
eight CSV files and 2,830,743 network flows. All files share the same 79-column
schema, and no structurally malformed rows were found, so the files can be read
consistently by the next stages of the project. The target contains 15 original
labels: `BENIGN` and 14 attack labels. However, the data cannot yet be considered
ready for splitting or model training because some attacks are extremely rare:
`Heartbleed` has only 11 examples and `Infiltration` has 36. In addition, the
three `Web Attack` labels contain a replacement character in the source CSVs,
which requires an explicit and traceable normalization rule. These findings show
that the dataset is structurally consistent, but they do not establish that it is
free from duplicates, non-finite values, class imbalance, or leakage risks.

The complete machine-readable results are available in
[`data-profile.json`](data-profile.json).
