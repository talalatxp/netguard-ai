# AI-11 final publication and reproducible release

## Scope

AI-11 closes the planned NetGuard AI research project. The current `0.2.0`
release additionally includes the later AI-15 individual explanations. AI-11
publishes the consolidated research report, model card, release notes, and a
machine-readable integrity manifest. It also provides a deterministic source-ZIP
builder and tests that fail when a listed source file, model artifact, frozen
report, threshold contract, or hash changes.

This is a local release preparation. It does not create a Git tag, GitHub release,
deployment, or public license on the user's behalf.

## Release contents

- `MODEL_CARD.md`: intended use, data, preprocessing, thresholds, metrics,
  failure modes, explainability, ethics, reproducibility, and license status.
- `reports/final-report.md`: end-to-end scientific narrative and conclusion.
- `release/RELEASE_NOTES.md`: version scope and exclusions.
- `release/release-files.txt`: sorted allowlist for the source bundle.
- `release/release-manifest.json`: SHA-256 and size for every bundled file,
  external dataset file, and learned model artifact.
- `scripts/build_release.py`: cross-platform deterministic manifest, ZIP, and
  checksum builder.
- `tests/test_build_release.py`: path-safety, deterministic-byte, and committed-
  manifest tests.

## Frozen scientific contract

The manifest confirms seed `42`, validation-first threshold selection with
minimum attack recall `0.80`, one-time final test use, unchanged post-test
thresholds, and the frozen feature-array SHA-256. Every learned artifact records
its evaluation, model name, path, size, hash, threshold, and final metrics.

## Distribution boundary

The source ZIP contains code, tests, reports, documentation, configuration, and
the release manifest. It excludes raw data, generated matrices, model binaries,
virtual environments, caches, and local outputs. External artifacts remain
reproducible and independently verifiable from the manifest.

No software or model license has been selected. Release metadata and a source ZIP
do not grant permission to reuse or redistribute the work. A public hosting step
should not describe the project as open source until the owner chooses a license.

## Verification commands

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe scripts/build_release.py check --require-models
.\.venv\Scripts\python.exe scripts/build_release.py build --require-models
```

The build writes the deterministic bundle and its checksum under ignored `dist/`.
Running the build twice without source changes must produce identical ZIP bytes.
