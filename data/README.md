# CIC-IDS2017 data

The raw dataset is intentionally excluded from Git. This directory documents
the exact source and the integrity checks required to reproduce the data used by
NetGuard AI.

## Selected distribution

- Dataset: `CIC-IDS2017`
- Publisher: Canadian Institute for Cybersecurity, University of New Brunswick
- Official dataset page: <https://www.unb.ca/cic/datasets/ids-2017.html>
- Official download portal: <https://cicresearch.ca/CICDataset/CIC-IDS-2017/>
- Required distribution: `MachineLearningCSV.zip`
- Downloaded at: `2026-09-08T14:57:47Z`
- Archive size: `235102953` bytes
- Official MD5: `4f83860afbf29cac8163854095bf6cf7`
- Archive SHA-256: `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928`
- Status: official archive downloaded, checksum verified, and contents inventoried

`MachineLearningCSV.zip` is selected because NetGuard AI operates on the
precomputed, labelled network-flow features intended for machine-learning use.
The PCAP captures and `GeneratedLabelledFlows.zip` are not required for the
initial experiment.

## Expected archive contents

The downloaded archive contains the following CSV files:

```text
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

The spelling and capitalization above are taken from the verified archive,
including `Infilteration`. Do not rename files before creating the inventory.

The archive contains eight CSV files totalling `884645759` extracted bytes. The
publisher's `MachineLearningCSV.md5` file refers internally to
`MachineLearningCVE.zip`; despite that naming mismatch, its MD5 digest matches
the downloaded `MachineLearningCSV.zip` byte for byte.

## Local layout

Store the official archive and its extracted contents under the ignored
`data/raw/` directory:

```text
data/
├── README.md
├── checksums.json
└── raw/
    ├── MachineLearningCSV.zip
    └── MachineLearningCSV/
```

`data/raw/` is excluded by `.gitignore`. `data/checksums.json` contains the
verified archive and per-CSV SHA-256 inventory and is committed to Git.

## Download and verification procedure

1. Open the official dataset page.
2. Follow **Download this dataset** to the CIC download portal.
3. Complete the publisher's required form.
4. Download `CSVs/MachineLearningCSV.zip` to `data/raw/` without renaming it.
5. Record the download time in UTC using ISO 8601.
6. Extract the archive beneath `data/raw/MachineLearningCSV/`.
7. Generate the archive and CSV inventory:

   ```powershell
   python scripts/hash_dataset.py `
     data/raw/MachineLearningCSV.zip `
     "data/raw/MachineLearningCSV/**/*.csv" `
     --output data/checksums.json
   ```

8. Confirm that the generated inventory contains one ZIP and eight CSV files.
9. Commit `data/README.md` and `data/checksums.json`, never `data/raw/`.

The inventory records each relative path, size in bytes, and SHA-256 digest.
A mismatch means the file must not be used until the difference is explained.

## Attribution

Use of CIC-IDS2017 should cite the paper requested by the publisher:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward
Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization," ICISSP, 2018.

The official page describes the files as publicly available for researchers and
requests this citation. Keeping raw files out of this repository also avoids
republishing the dataset without a separate redistribution review.
