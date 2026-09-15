"""Build reproducible random and temporal split manifests for CIC-IDS2017."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from audit_dataset import decode_csv_line, display_path, expand_inputs
from audit_feature_leakage import feature_columns, feature_hash


RANDOM_SEED = 42
TRAIN_CUTOFF = 0.70
VALIDATION_CUTOFF = 0.85
TEMPORAL_PARTITIONS = {
    "Monday": "train",
    "Tuesday": "train",
    "Wednesday": "train",
    "Thursday": "validation",
    "Friday": "test",
}
EXPECTED_FILE_ORDER = (
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)
FILE_ORDER = {name: index for index, name in enumerate(EXPECTED_FILE_ORDER)}
CONSTANT_FEATURE_NAMES = frozenset(
    {
        "Bwd PSH Flags",
        "Bwd URG Flags",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
    }
)
CANONICAL_LABELS = {
    "BENIGN": "BENIGN",
    "Bot": "Bot",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS Hulk": "DoS Hulk",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "DoS slowloris": "DoS slowloris",
    "FTP-Patator": "FTP-Patator",
    "Heartbleed": "Heartbleed",
    "Infiltration": "Infiltration",
    "PortScan": "PortScan",
    "SSH-Patator": "SSH-Patator",
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    "Web Attack � XSS": "Web Attack - XSS",
}
PARTITIONS = ("train", "validation", "test")


def partition_from_unit_interval(value: float) -> str:
    """Map a value in [0, 1) to the frozen 70/15/15 split intervals."""
    if not 0.0 <= value < 1.0:
        raise ValueError("value must be in the interval [0, 1)")
    if value < TRAIN_CUTOFF:
        return "train"
    if value < VALIDATION_CUTOFF:
        return "validation"
    return "test"


def random_partition(feature_hash_value: str, seed: int = RANDOM_SEED) -> str:
    """Assign one feature-hash group reproducibly to a random partition."""
    if len(feature_hash_value) != hashlib.sha256().digest_size * 2:
        raise ValueError("feature_hash must be a 64-character SHA-256 digest")
    try:
        fingerprint = bytes.fromhex(feature_hash_value)
    except ValueError as error:
        raise ValueError("feature_hash must be a hexadecimal SHA-256 digest") from error
    if len(fingerprint) != hashlib.sha256().digest_size:
        raise ValueError("feature_hash must be a 64-character SHA-256 digest")

    seeded_digest = hashlib.sha256(
        str(seed).encode("ascii") + b":" + fingerprint
    ).digest()
    numerator = int.from_bytes(seeded_digest[:8], byteorder="big", signed=False)
    return partition_from_unit_interval(numerator / 2**64)


def temporal_partition(path: Path) -> str:
    """Assign a CIC-IDS2017 CSV to the frozen partition for its capture day."""
    day, separator, _remainder = path.name.partition("-")
    if not separator or day not in TEMPORAL_PARTITIONS:
        raise ValueError(f"unrecognized CIC-IDS2017 capture day: {path.name}")
    return TEMPORAL_PARTITIONS[day]


def chronological_paths(paths: list[Path]) -> list[Path]:
    """Return known files in the deterministic order used for deduplication."""
    names = [path.name for path in paths]
    if len(names) != len(set(names)):
        raise ValueError("duplicate CIC-IDS2017 filenames were supplied")
    unknown = sorted(set(names) - set(EXPECTED_FILE_ORDER))
    if unknown:
        raise ValueError(f"unexpected CIC-IDS2017 files: {', '.join(unknown)}")
    return sorted(paths, key=lambda path: FILE_ORDER[path.name])


def validate_complete_file_set(paths: list[Path]) -> None:
    """Require the exact verified eight-file MachineLearningCSV distribution."""
    supplied = {path.name for path in paths}
    expected = set(EXPECTED_FILE_ORDER)
    missing = sorted(expected - supplied)
    extra = sorted(supplied - expected)
    if missing or extra or len(paths) != len(EXPECTED_FILE_ORDER):
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected: {', '.join(extra)}")
        message = "; ".join(details) or "duplicate filenames"
        raise ValueError(f"dataset file set differs from verified snapshot ({message})")


def normalize_label(raw_label: str) -> tuple[str, int]:
    """Return the frozen canonical label and binary target without changing raw text."""
    source_label = raw_label.strip()
    try:
        canonical = CANONICAL_LABELS[source_label]
    except KeyError:
        raise ValueError(f"unknown CIC-IDS2017 label: {source_label!r}") from None
    return canonical, int(canonical != "BENIGN")


def prepared_feature_indices(header: list[str]) -> tuple[int, list[int]]:
    """Select the planned numeric inputs and validate their unique names."""
    label_index, indices, _duplicate_pair = feature_columns(header)
    indices = [
        index
        for index in indices
        if header[index].strip() not in CONSTANT_FEATURE_NAMES
    ]
    names = [header[index].strip() for index in indices]
    if len(names) != len(set(names)):
        raise ValueError("prepared feature names are not unique")
    return label_index, indices


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partition_summary(
    connection: sqlite3.Connection, column: str, *, novel_only: bool = False
) -> dict[str, dict[str, object]]:
    if column not in {"random_partition", "temporal_partition"}:
        raise ValueError(f"unsupported partition column: {column}")
    condition = "WHERE temporal_novel = 1" if novel_only else ""
    summaries: dict[str, dict[str, object]] = {
        partition: {
            "rows": 0,
            "benign_rows": 0,
            "attack_rows": 0,
            "attack_rate": 0.0,
            "labels": {},
        }
        for partition in PARTITIONS
    }

    for partition, target, count in connection.execute(
        f"SELECT {column}, target, COUNT(*) FROM retained_rows "
        f"{condition} GROUP BY {column}, target"
    ):
        summary = summaries[partition]
        summary["rows"] += count
        key = "attack_rows" if target == 1 else "benign_rows"
        summary[key] += count

    for partition, label, count in connection.execute(
        f"SELECT {column}, label_canonical, COUNT(*) FROM retained_rows "
        f"{condition} GROUP BY {column}, label_canonical"
    ):
        summaries[partition]["labels"][label] = count

    for summary in summaries.values():
        rows = int(summary["rows"])
        summary["attack_rate"] = (
            int(summary["attack_rows"]) / rows if rows else 0.0
        )
    return summaries


def build_split_manifest(
    paths: list[Path], root: Path, manifest_output: Path, seed: int = RANDOM_SEED
) -> dict[str, object]:
    """Deduplicate rows, assign both evaluations, and write a local manifest."""
    ordered_paths = chronological_paths(paths)
    root = root.resolve()
    manifest_output = manifest_output.resolve()
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    seen_full_rows: set[bytes] = set()
    removed_by_label: Counter[str] = Counter()
    file_results: list[dict[str, object]] = []
    raw_rows = 0
    retained_rows = 0
    reference_header: list[str] | None = None
    feature_names: list[str] = []

    with tempfile.TemporaryDirectory(prefix="netguard-splits-") as temp_directory:
        connection = sqlite3.connect(Path(temp_directory) / "splits.sqlite3")
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute(
                "CREATE TABLE retained_rows ("
                "sequence INTEGER PRIMARY KEY, file_index INTEGER NOT NULL, "
                "line_number INTEGER NOT NULL, label_raw TEXT NOT NULL, "
                "label_canonical TEXT NOT NULL, target INTEGER NOT NULL, "
                "feature_hash BLOB NOT NULL, random_partition TEXT NOT NULL, "
                "temporal_partition TEXT NOT NULL, temporal_novel INTEGER)"
            )

            with connection:
                for file_index, path in enumerate(ordered_paths):
                    file_raw_rows = 0
                    file_retained_rows = 0
                    file_removed_by_label: Counter[str] = Counter()
                    displayed_path = display_path(path, root)
                    temporal = temporal_partition(path)
                    batch: list[tuple[object, ...]] = []

                    with path.open("rb") as handle:
                        raw_header = handle.readline()
                        if not raw_header:
                            raise ValueError(f"CSV is empty: {path}")
                        header = decode_csv_line(raw_header, first_line=True)
                        normalized_header = [name.strip() for name in header]
                        label_index, indices = prepared_feature_indices(header)
                        _label_index, _all_indices, duplicate_pair = feature_columns(header)
                        if reference_header is None:
                            reference_header = normalized_header
                            feature_names = [normalized_header[index] for index in indices]
                        elif normalized_header != reference_header:
                            raise ValueError(f"schema differs from the first CSV: {path}")

                        for line_number, raw_line in enumerate(handle, start=2):
                            raw_rows += 1
                            file_raw_rows += 1
                            row = decode_csv_line(raw_line)
                            if len(row) != len(header):
                                raise ValueError(f"malformed row: {path}:{line_number}")
                            left, right = duplicate_pair
                            if row[left] != row[right]:
                                raise ValueError(
                                    f"Fwd Header Length copies differ: {path}:{line_number}"
                                )

                            canonical_label, target = normalize_label(row[label_index])
                            row_fingerprint = hashlib.sha256(
                                raw_line.rstrip(b"\r\n")
                            ).digest()
                            if row_fingerprint in seen_full_rows:
                                removed_by_label[canonical_label] += 1
                                file_removed_by_label[canonical_label] += 1
                                continue
                            seen_full_rows.add(row_fingerprint)

                            features = feature_hash(row, indices)
                            retained_rows += 1
                            file_retained_rows += 1
                            batch.append(
                                (
                                    retained_rows,
                                    file_index,
                                    line_number,
                                    row[label_index],
                                    canonical_label,
                                    target,
                                    features,
                                    random_partition(features.hex(), seed),
                                    temporal,
                                    None,
                                )
                            )
                            if len(batch) == 10_000:
                                connection.executemany(
                                    "INSERT INTO retained_rows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    batch,
                                )
                                batch.clear()
                        if batch:
                            connection.executemany(
                                "INSERT INTO retained_rows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                batch,
                            )

                    file_results.append(
                        {
                            "path": displayed_path,
                            "temporal_partition": temporal,
                            "raw_rows": file_raw_rows,
                            "retained_rows": file_retained_rows,
                            "exact_duplicates_removed": file_raw_rows
                            - file_retained_rows,
                            "duplicates_removed_by_label": dict(
                                sorted(file_removed_by_label.items())
                            ),
                        }
                    )

            connection.execute(
                "CREATE INDEX retained_feature_partition "
                "ON retained_rows(feature_hash, temporal_partition)"
            )
            connection.execute(
                "CREATE TABLE feature_presence AS "
                "SELECT feature_hash, "
                "MAX(temporal_partition = 'train') AS has_train, "
                "MAX(temporal_partition = 'validation') AS has_validation "
                "FROM retained_rows GROUP BY feature_hash"
            )
            connection.execute(
                "CREATE UNIQUE INDEX feature_presence_hash "
                "ON feature_presence(feature_hash)"
            )
            connection.execute(
                "UPDATE retained_rows SET temporal_novel = CASE "
                "WHEN temporal_partition = 'train' THEN 1 "
                "WHEN temporal_partition = 'validation' THEN NOT EXISTS ("
                "SELECT 1 FROM feature_presence p WHERE p.feature_hash = retained_rows.feature_hash "
                "AND p.has_train = 1) "
                "ELSE NOT EXISTS (SELECT 1 FROM feature_presence p "
                "WHERE p.feature_hash = retained_rows.feature_hash "
                "AND (p.has_train = 1 OR p.has_validation = 1)) END"
            )
            connection.commit()

            with tempfile.NamedTemporaryFile(
                prefix=manifest_output.name + ".",
                suffix=".tmp",
                dir=manifest_output.parent,
                delete=False,
            ) as temp_handle:
                temp_manifest = Path(temp_handle.name)
            try:
                with temp_manifest.open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.writer(handle, lineterminator="\n")
                    writer.writerow(
                        [
                            "source_file",
                            "line_number",
                            "label_raw",
                            "label_canonical",
                            "target",
                            "feature_hash",
                            "random_partition",
                            "temporal_partition",
                            "temporal_novel",
                        ]
                    )
                    for row in connection.execute(
                        "SELECT file_index, line_number, label_raw, label_canonical, "
                        "target, HEX(feature_hash), random_partition, temporal_partition, "
                        "temporal_novel FROM retained_rows ORDER BY sequence"
                    ):
                        file_index, *values = row
                        values[4] = values[4].lower()
                        writer.writerow([file_results[file_index]["path"], *values])
                temp_manifest.replace(manifest_output)
            finally:
                if temp_manifest.exists():
                    temp_manifest.unlink()

            random_overlap_groups = connection.execute(
                "SELECT COUNT(*) FROM (SELECT feature_hash FROM retained_rows "
                "GROUP BY feature_hash HAVING COUNT(DISTINCT random_partition) > 1)"
            ).fetchone()[0]
            validation_seen = connection.execute(
                "SELECT COUNT(DISTINCT r.feature_hash), COUNT(*) FROM retained_rows r "
                "JOIN feature_presence p ON p.feature_hash = r.feature_hash "
                "WHERE r.temporal_partition = 'validation' AND p.has_train = 1"
            ).fetchone()
            test_seen = connection.execute(
                "SELECT COUNT(DISTINCT r.feature_hash), COUNT(*) FROM retained_rows r "
                "JOIN feature_presence p ON p.feature_hash = r.feature_hash "
                "WHERE r.temporal_partition = 'test' "
                "AND (p.has_train = 1 OR p.has_validation = 1)"
            ).fetchone()
            conflicting = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(group_rows), 0) FROM ("
                "SELECT COUNT(*) AS group_rows FROM retained_rows GROUP BY feature_hash "
                "HAVING MIN(target) != MAX(target))"
            ).fetchone()

            report = {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "method": {
                    "full_row_deduplication": (
                        "SHA-256 of raw CSV row bytes without the line ending; "
                        "retain first occurrence in explicit file and row order"
                    ),
                    "feature_hash": (
                        "SHA-256 of JSON-serialized original feature-cell strings "
                        "after excluding Label, the second Fwd Header Length, and "
                        "eight globally constant columns"
                    ),
                    "random_assignment": (
                        "SHA-256(seed + ':' + feature_hash), first 64 bits mapped "
                        "to frozen 70/15/15 intervals"
                    ),
                    "temporal_novel": (
                        "validation hash absent from train; test hash absent from "
                        "train and validation"
                    ),
                },
                "configuration": {
                    "random_seed": seed,
                    "random_target_fractions": {
                        "train": TRAIN_CUTOFF,
                        "validation": VALIDATION_CUTOFF - TRAIN_CUTOFF,
                        "test": 1.0 - VALIDATION_CUTOFF,
                    },
                    "ordered_files": [item["path"] for item in file_results],
                    "complete_verified_file_set": {
                        path.name for path in ordered_paths
                    }
                    == set(EXPECTED_FILE_ORDER),
                },
                "raw_rows": raw_rows,
                "retained_rows": retained_rows,
                "exact_duplicates_removed": raw_rows - retained_rows,
                "duplicates_removed_by_label": dict(sorted(removed_by_label.items())),
                "feature_count": len(feature_names),
                "feature_names": feature_names,
                "files": file_results,
                "random": {
                    "partitions": partition_summary(connection, "random_partition"),
                    "shared_feature_hash_groups": random_overlap_groups,
                },
                "temporal": {
                    "partitions": partition_summary(connection, "temporal_partition"),
                    "novel_partitions": partition_summary(
                        connection, "temporal_partition", novel_only=True
                    ),
                    "validation_hashes_seen_in_train": validation_seen[0],
                    "validation_rows_seen_in_train": validation_seen[1],
                    "test_hashes_seen_earlier": test_seen[0],
                    "test_rows_seen_earlier": test_seen[1],
                },
                "conflicting_binary_target_groups": conflicting[0],
                "rows_in_conflicting_binary_target_groups": conflicting[1],
                "manifest": {
                    "path": display_path(manifest_output, root),
                    "size_bytes": manifest_output.stat().st_size,
                    "sha256": file_sha256(manifest_output),
                    "row_count": retained_rows,
                },
            }
        finally:
            connection.close()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="CSV paths or glob patterns")
    parser.add_argument(
        "--manifest-output",
        type=Path,
        required=True,
        help="Write retained-row CSV manifest",
    )
    parser.add_argument(
        "--report-output", type=Path, required=True, help="Write JSON split summary"
    )
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    try:
        paths = expand_inputs(args.inputs)
        validate_complete_file_set(paths)
        report = build_split_manifest(
            paths, Path.cwd(), args.manifest_output, seed=args.seed
        )
    except (FileNotFoundError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None

    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
