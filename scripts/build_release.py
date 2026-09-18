"""Build and verify the deterministic NetGuard AI research release."""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

from train_baselines import file_sha256


SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
LEARNED_MODELS = (
    "logistic_regression_sgd",
    "random_forest",
    "hist_gradient_boosting",
)
EVALUATIONS = ("random", "temporal")


def read_release_paths(root: Path, list_path: Path) -> tuple[str, ...]:
    values = tuple(
        line.strip()
        for line in list_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    if not values:
        raise ValueError("release file list is empty")
    if list(values) != sorted(values):
        raise ValueError("release file list must be sorted")
    if len(values) != len(set(values)):
        raise ValueError("release file list contains duplicates")
    for value in values:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError(f"unsafe release path: {value}")
        if value == "release/release-manifest.json":
            raise ValueError("release manifest must not hash itself")
        if not (root / value).is_file():
            raise FileNotFoundError(f"release file does not exist: {value}")
    return values


def file_record(root: Path, relative_path: str) -> dict[str, object]:
    path = root / relative_path
    return {
        "path": relative_path,
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def learned_artifact_records(
    root: Path,
    ai07: dict[str, object],
    ai08: dict[str, object],
    require_models: bool,
) -> list[dict[str, object]]:
    reports = {
        "logistic_regression_sgd": ai07,
        "random_forest": ai08,
        "hist_gradient_boosting": ai08,
    }
    records: list[dict[str, object]] = []
    for evaluation in EVALUATIONS:
        for model_name in LEARNED_MODELS:
            model = reports[model_name]["evaluations"][evaluation]["models"][
                model_name
            ]
            artifact_path = str(model["artifact"])
            expected_hash = str(model["artifact_sha256"])
            artifact = root / artifact_path
            if require_models and not artifact.is_file():
                raise FileNotFoundError(f"required model artifact is missing: {artifact_path}")
            if artifact.is_file():
                actual_hash = file_sha256(artifact)
                if actual_hash != expected_hash:
                    raise ValueError(f"model artifact hash mismatch: {artifact_path}")
                size_bytes = artifact.stat().st_size
            else:
                size_bytes = None
            records.append(
                {
                    "evaluation": evaluation,
                    "model": model_name,
                    "path": artifact_path,
                    "size_bytes": size_bytes,
                    "sha256": expected_hash,
                    "threshold": model["threshold_selection"]["threshold"],
                    "test_metrics": {
                        name: model["test"][name]
                        for name in (
                            "attack_precision",
                            "attack_recall",
                            "attack_f1",
                            "pr_auc",
                            "false_positive_count",
                        )
                    },
                }
            )
    return records


def build_manifest(
    root: Path,
    release_files_path: Path,
    require_models: bool,
) -> dict[str, object]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise ValueError(f"VERSION is not semantic versioning: {version!r}")
    release_paths = read_release_paths(root, release_files_path)
    checksums = json.loads((root / "data/checksums.json").read_text(encoding="utf-8"))
    ai07_path = root / "reports/ai-07-baseline-results.json"
    ai08_path = root / "reports/ai-08-model-comparison-results.json"
    ai09_path = root / "reports/ai-09-error-analysis.json"
    ai07 = json.loads(ai07_path.read_text(encoding="utf-8"))
    ai08 = json.loads(ai08_path.read_text(encoding="utf-8"))
    ai09 = json.loads(ai09_path.read_text(encoding="utf-8"))
    if ai07["contract"]["test_used"] is not True:
        raise ValueError("AI-07 final test contract is incomplete")
    if ai08["contract"]["test_used"] is not True:
        raise ValueError("AI-08 final test contract is incomplete")
    if ai09["contract"]["thresholds_changed"] is not False:
        raise ValueError("AI-09 changed a frozen threshold")
    if ai07["seed"] != ai08["seed"] or ai08["seed"] != ai09["seed"]:
        raise ValueError("experiment seeds differ")

    return {
        "schema_version": 1,
        "release": {
            "name": "NetGuard AI",
            "version": version,
            "kind": "research prototype",
            "license": "not declared",
        },
        "integrity": {
            "algorithm": "SHA-256",
            "deterministic_zip_timestamp": "1980-01-01T00:00:00",
        },
        "experiment_contract": {
            "seed": ai09["seed"],
            "minimum_attack_recall_for_threshold_selection": 0.8,
            "test_evaluated_once": True,
            "post_test_thresholds_changed": False,
            "feature_array_sha256": ai09["matrix_arrays_sha256"]["features"],
        },
        "dataset_files": checksums["files"],
        "frozen_reports": [
            file_record(root, "reports/ai-07-baseline-results.json"),
            file_record(root, "reports/ai-08-model-comparison-results.json"),
            file_record(root, "reports/ai-09-error-analysis.json"),
        ],
        "external_model_artifacts": learned_artifact_records(
            root, ai07, ai08, require_models
        ),
        "included_files": [file_record(root, path) for path in release_paths],
        "reproduction": {
            "install": ".\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt",
            "test": ".\\.venv\\Scripts\\python.exe -m unittest discover -s tests -q",
            "release_check": ".\\.venv\\Scripts\\python.exe scripts/build_release.py check --require-models",
            "demo": ".\\.venv\\Scripts\\python.exe -m streamlit run app.py",
        },
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(manifest_bytes(value))
    temporary.replace(path)


def write_deterministic_bundle(
    root: Path,
    release_paths: tuple[str, ...],
    manifest_path: Path,
    output_path: Path,
    version: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"netguard-ai-{version}"
    entries = [*release_paths, manifest_path.relative_to(root).as_posix()]
    with zipfile.ZipFile(
        output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for relative_path in sorted(entries):
            info = zipfile.ZipInfo(
                f"{prefix}/{relative_path}", date_time=FIXED_ZIP_TIMESTAMP
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (root / relative_path).read_bytes())


def manifest_bytes(manifest: dict[str, object]) -> bytes:
    return (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "check"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--release-files",
        type=Path,
        default=Path("release/release-files.txt"),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("release/release-manifest.json"),
    )
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--require-models", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    release_files_path = root / args.release_files
    manifest_path = root / args.manifest
    manifest = build_manifest(root, release_files_path, args.require_models)
    if args.command == "check":
        if not manifest_path.is_file():
            raise FileNotFoundError(f"release manifest does not exist: {manifest_path}")
        if manifest_path.read_bytes() != manifest_bytes(manifest):
            raise ValueError("release manifest is stale")
        print(f"Release {manifest['release']['version']} manifest verified")
        return

    write_json(manifest_path, manifest)
    version = str(manifest["release"]["version"])
    release_paths = read_release_paths(root, release_files_path)
    bundle = root / args.dist_dir / f"netguard-ai-{version}-source.zip"
    write_deterministic_bundle(root, release_paths, manifest_path, bundle, version)
    checksum = file_sha256(bundle)
    sums_path = root / args.dist_dir / "SHA256SUMS"
    sums_path.write_bytes(f"{checksum}  {bundle.name}\n".encode("utf-8"))
    print(f"Release manifest: {manifest_path}")
    print(f"Source bundle: {bundle}")
    print(f"Source bundle SHA-256: {checksum}")


if __name__ == "__main__":
    main()
