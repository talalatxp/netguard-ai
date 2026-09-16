"""Materialize one compact model matrix aligned with the frozen split manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from datetime import datetime, timezone
from itertools import groupby, tee
from pathlib import Path

import numpy as np

from audit_dataset import decode_csv_line
from audit_feature_leakage import feature_columns, feature_hash
from build_splits import CANONICAL_LABELS, normalize_label, prepared_feature_indices
from model_data import ManifestRecord, iter_manifest_records, iter_selected_raw_lines


PARTITION_CODES = {"train": 0, "validation": 1, "test": 2}
ARRAY_FILES = {
    "features": "features.npy",
    "target": "target.npy",
    "random_partition": "random_partition.npy",
    "temporal_partition": "temporal_partition.npy",
    "temporal_novel": "temporal_novel.npy",
    "label_code": "label_code.npy",
    "source_file_code": "source_file_code.npy",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_source_path(root: Path, relative_path: Path) -> Path:
    """Resolve a manifest source path while preventing paths outside the root."""
    root = root.resolve()
    if relative_path.is_absolute():
        raise ValueError(f"manifest source path must be relative: {relative_path}")
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"manifest source path escapes root: {relative_path}") from error
    return resolved


def _open_arrays(directory: Path, rows: int, features: int) -> dict[str, np.memmap]:
    shapes = {
        "features": (rows, features),
        "target": (rows,),
        "random_partition": (rows,),
        "temporal_partition": (rows,),
        "temporal_novel": (rows,),
        "label_code": (rows,),
        "source_file_code": (rows,),
    }
    dtypes = {"features": np.float32} | {
        name: np.uint8 for name in shapes if name != "features"
    }
    return {
        name: np.lib.format.open_memmap(
            directory / ARRAY_FILES[name], mode="w+", dtype=dtypes[name], shape=shape
        )
        for name, shape in shapes.items()
    }


def build_model_matrix(
    manifest_path: Path,
    split_summary_path: Path,
    root: Path,
    output_directory: Path,
) -> dict[str, object]:
    """Create feature and metadata arrays without duplicating evaluation splits."""
    output_directory = output_directory.resolve()
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FileExistsError(f"model matrix output is not empty: {output_directory}")

    summary = json.loads(split_summary_path.read_text(encoding="utf-8"))
    expected_rows = int(summary["retained_rows"])
    expected_feature_names = list(summary["feature_names"])
    expected_feature_count = int(summary["feature_count"])
    if len(expected_feature_names) != expected_feature_count:
        raise ValueError("split summary feature count does not match feature names")

    output_directory.mkdir(parents=True, exist_ok=True)

    labels = sorted(set(CANONICAL_LABELS.values()))
    label_codes = {label: index for index, label in enumerate(labels)}
    source_files: list[str] = []
    reference_header: list[str] | None = None
    written = 0

    with tempfile.TemporaryDirectory(
        prefix="netguard-model-matrix-", dir=output_directory.parent
    ) as temporary:
        temporary_path = Path(temporary)
        arrays = _open_arrays(temporary_path, expected_rows, expected_feature_count)
        seen_source_files: set[Path] = set()

        records = iter_manifest_records(manifest_path)
        for relative_path, record_group in groupby(
            records, key=lambda record: record.source_file
        ):
            if relative_path in seen_source_files:
                raise ValueError(
                    f"manifest source file is not contiguous: {relative_path}"
                )
            seen_source_files.add(relative_path)
            source_path = resolve_source_path(root, relative_path)
            source_file_code = len(source_files)
            source_files.append(relative_path.as_posix())

            with source_path.open("rb") as source_handle:
                raw_header = source_handle.readline()
            if not raw_header:
                raise ValueError(f"CSV is empty: {source_path}")
            header = decode_csv_line(raw_header, first_line=True)
            normalized_header = [name.strip() for name in header]
            label_index, feature_indices = prepared_feature_indices(header)
            _label_index, _all_indices, duplicate_pair = feature_columns(header)
            feature_names = [normalized_header[index] for index in feature_indices]
            if feature_names != expected_feature_names:
                raise ValueError(f"prepared feature schema differs: {source_path}")
            if reference_header is None:
                reference_header = normalized_header
            elif normalized_header != reference_header:
                raise ValueError(f"CSV schema differs from first source: {source_path}")

            metadata_records, line_records = tee(record_group)
            selected_lines = iter_selected_raw_lines(
                source_path, (record.line_number for record in line_records)
            )
            for record, (line_number, raw_line) in zip(
                metadata_records, selected_lines, strict=True
            ):
                if written >= expected_rows:
                    raise ValueError("manifest contains more rows than split summary")
                row = decode_csv_line(raw_line)
                if len(row) != len(header):
                    raise ValueError(f"malformed row: {source_path}:{line_number}")
                left, right = duplicate_pair
                if row[left] != row[right]:
                    raise ValueError(
                        f"Fwd Header Length copies differ: {source_path}:{line_number}"
                    )
                canonical_label, target = normalize_label(row[label_index])
                if canonical_label != record.label_canonical or target != record.target:
                    raise ValueError(
                        f"manifest label mismatch: {source_path}:{line_number}"
                    )
                if feature_hash(row, feature_indices).hex() != record.feature_hash:
                    raise ValueError(
                        f"manifest feature hash mismatch: {source_path}:{line_number}"
                    )
                try:
                    values = np.fromiter(
                        (float(row[index]) for index in feature_indices),
                        dtype=np.float32,
                        count=expected_feature_count,
                    )
                except ValueError as error:
                    raise ValueError(
                        f"non-numeric model feature: {source_path}:{line_number}"
                    ) from error

                arrays["features"][written] = values
                arrays["target"][written] = target
                arrays["random_partition"][written] = PARTITION_CODES[
                    record.random_partition
                ]
                arrays["temporal_partition"][written] = PARTITION_CODES[
                    record.temporal_partition
                ]
                arrays["temporal_novel"][written] = int(record.temporal_novel)
                arrays["label_code"][written] = label_codes[canonical_label]
                arrays["source_file_code"][written] = source_file_code
                written += 1

        if written != expected_rows:
            raise ValueError(
                f"manifest row count differs from split summary: {written} != {expected_rows}"
            )
        for array in arrays.values():
            array.flush()
        del array
        del arrays

        metadata: dict[str, object] = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "rows": written,
            "feature_count": expected_feature_count,
            "feature_names": expected_feature_names,
            "feature_dtype": "float32",
            "partition_codes": PARTITION_CODES,
            "label_codes": label_codes,
            "source_files": source_files,
            "manifest": {
                "path": manifest_path.as_posix(),
                "size_bytes": manifest_path.stat().st_size,
                "sha256": file_sha256(manifest_path),
            },
            "arrays": {},
        }
        array_metadata = metadata["arrays"]
        assert isinstance(array_metadata, dict)
        for name, filename in ARRAY_FILES.items():
            path = temporary_path / filename
            array_metadata[name] = {
                "filename": filename,
                "size_bytes": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        (temporary_path / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        for path in temporary_path.iterdir():
            shutil.move(str(path), output_directory / path.name)

    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=Path("data/processed/split-manifest.csv")
    )
    parser.add_argument(
        "--split-summary", type=Path, default=Path("reports/split-summary.json")
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/processed/model-matrix")
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metadata = build_model_matrix(
        args.manifest, args.split_summary, args.root, args.output_dir
    )
    print(json.dumps(metadata, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
