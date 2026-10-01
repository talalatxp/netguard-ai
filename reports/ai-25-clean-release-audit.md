# AI-25 clean release audit

## Scope

AI-25 verifies that the NetGuard AI source release can be installed and tested
outside the development checkout. It also separates the project license
from the terms that apply to CIC-IDS2017.

## Clean-environment verification

The `0.2.0` source ZIP was extracted into a newly created temporary directory on
Windows with Python 3.14.6. A new virtual environment was created and every
dependency in `requirements.txt` was installed from scratch.

The first clean run exposed two hidden dependencies on external model binaries:

- the committed-manifest test required all six ignored model files even though
  the source release intentionally excludes them;
- the Streamlit upload integration test attempted inference with the absent
  random HGB artifact.

The release checks were corrected without weakening the local artifact audit:

- source-only manifest verification retains the previously verified model sizes
  and still checks paths, hashes, thresholds, metrics, and every included file;
- a partial set of model binaries is rejected;
- the Streamlit scoring test is skipped only when its declared external model is
  absent;
- `check --require-models` still requires and hashes all six model artifacts.

Final clean-source result:

- dependency installation: passed;
- `pip check`: passed;
- source compilation: passed;
- 70 tests: passed, with one model-dependent integration test explicitly
  skipped because model binaries are outside the source ZIP;
- source-only release-manifest check: passed.

Final development-checkout result:

- 70 tests: passed with no skip;
- strict release check with all six external model artifacts: passed.

## Dataset terms

The official Canadian Institute for Cybersecurity dataset catalogue states that
its datasets may be redistributed, republished, and mirrored, including for
commercial use, provided that use or redistribution includes the dataset and
research-paper citation. The CIC-IDS2017 page identifies the required paper.

The raw dataset is not included in this repository. Any project license applies
only to this repository's original code and associated documentation; it does
not replace the CIC attribution requirement.

Official references:

- <https://www.unb.ca/cic/datasets/>
- <https://www.unb.ca/cic/datasets/ids-2017.html>

## Project-license decision

Selected option: **MIT License** for the original code and associated
documentation.

Rationale:

- it is short and widely understood for a public portfolio project;
- it allows use, modification, and redistribution while retaining the copyright
  and license notice;
- it does not claim ownership of CIC-IDS2017;
- trained model binaries remain excluded from this source release.

The canonical license text is stored in `LICENSE`. It does not apply to
CIC-IDS2017 or change the dataset publisher's attribution requirements.

## Release status

AI-25 is complete:

- the clean source environment passed;
- the MIT License and notices were added;
- the machine-readable manifest and deterministic source ZIP were rebuilt and
  rechecked.

Creating the version tag and GitHub Release is the separate publication step
scheduled after the final commit is present on the remote.
