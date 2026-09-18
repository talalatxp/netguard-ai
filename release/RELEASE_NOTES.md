# NetGuard AI 0.2.0

This is the first reproducible research release of NetGuard AI.

## Included

- official CIC-IDS2017 provenance and checksum inventory;
- data-quality and feature-leakage audits;
- deterministic group-aware random and chronological split contracts;
- leakage-safe preprocessing and frozen baseline/tree experiments;
- one-time final test records and attack-family error analysis;
- deterministic individual SHAP explanations for correct and incorrect HGB decisions;
- local explanatory Streamlit demo;
- model card and final research report;
- deterministic release manifest and source-bundle builder;
- automated unit and Streamlit integration tests.

## Not included

- raw CIC-IDS2017 files;
- generated split manifests and model matrices;
- trained model binaries;
- a software or model license;
- production deployment or live packet capture.

The omitted data and model artifacts are reproducible locally. Their exact
filenames, sizes, and SHA-256 hashes are recorded in `release-manifest.json`.

## Central result

Random HGB reaches precision 0.9999 and recall 0.8734. At the frozen temporal
threshold, HGB reaches precision 0.9921 but recall 0.0517 on Friday. The release
therefore makes no production-readiness claim.
