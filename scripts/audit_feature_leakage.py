"""Find repeated feature vectors and conflicting labels in CIC-IDS2017 CSVs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from audit_dataset import decode_csv_line, display_path, expand_inputs, find_label_index


def feature_columns(header: list[str]) -> tuple[int, list[int], tuple[int, int]]:
    """Validate the schema and omit Label and the redundant header-length copy."""
    normalized = [name.strip() for name in header]
    label_index = find_label_index(header)
    positions = [
        index for index, name in enumerate(normalized) if name == "Fwd Header Length"
    ]
    if len(positions) != 2:
        raise ValueError("Expected exactly two Fwd Header Length columns")
    if len(set(normalized)) != len(normalized) - 1:
        raise ValueError("Unexpected duplicate normalized column names")
    indices = [
        index
        for index in range(len(header))
        if index not in (label_index, positions[1])
    ]
    return label_index, indices, (positions[0], positions[1])


def feature_hash(row: list[str], indices: list[int]) -> bytes:
    """Hash an unambiguous ordered serialization of the original cell strings."""
    values = [row[index] for index in indices]
    encoded = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).digest()


def group_record(
    fingerprint: bytes, observations: list[tuple[str, int, int]], files: list[str]
) -> dict[str, object]:
    labels = Counter(label for label, _file_index, _line in observations)
    locations = [
        {"file": files[file_index], "line": line}
        for _label, file_index, line in observations
    ]
    return {
        "feature_hash": fingerprint.hex(),
        "row_count": len(observations),
        "label_counts": dict(sorted(labels.items())),
        "locations": locations,
        "cross_file": len({file_index for _label, file_index, _line in observations}) > 1,
    }


def summarize_groups(
    connection: sqlite3.Connection, files: list[str], details: TextIO | None
) -> dict[str, object]:
    summary: dict[str, object] = {
        "repeated_feature_groups": 0,
        "repeated_feature_rows": 0,
        "same_label_groups": 0,
        "same_label_rows": 0,
        "conflicting_label_groups": 0,
        "conflicting_label_rows": 0,
        "cross_file_groups": 0,
        "examples": {"same_label": [], "conflicting_labels": []},
    }
    cursor = connection.execute(
        "SELECT fingerprint, label, file_index, line_number "
        "FROM observations ORDER BY fingerprint, file_index, line_number"
    )
    current_hash: bytes | None = None
    current_rows: list[tuple[str, int, int]] = []

    def finish_group() -> None:
        if current_hash is None or len(current_rows) < 2:
            return
        record = group_record(current_hash, current_rows, files)
        category = (
            "conflicting_labels"
            if len(record["label_counts"]) > 1
            else "same_label"
        )
        prefix = "conflicting_label" if category == "conflicting_labels" else "same_label"
        summary["repeated_feature_groups"] += 1
        summary["repeated_feature_rows"] += len(current_rows)
        summary[f"{prefix}_groups"] += 1
        summary[f"{prefix}_rows"] += len(current_rows)
        summary["cross_file_groups"] += int(record["cross_file"])
        if len(summary["examples"][category]) < 5:
            summary["examples"][category].append(record)
        if details is not None:
            details.write(json.dumps(record, ensure_ascii=False) + "\n")

    for fingerprint, label, file_index, line_number in cursor:
        if current_hash is not None and fingerprint != current_hash:
            finish_group()
            current_rows = []
        current_hash = fingerprint
        current_rows.append((label, file_index, line_number))
    finish_group()
    return summary


def audit_feature_leakage(
    paths: list[Path], root: Path, details: TextIO | None = None
) -> dict[str, object]:
    files = [display_path(path, root) for path in paths]
    reference_header: list[str] | None = None
    total_rows = 0

    with tempfile.TemporaryDirectory(prefix="netguard-feature-audit-") as temp_dir:
        connection = sqlite3.connect(Path(temp_dir) / "observations.sqlite3")
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute(
                "CREATE TABLE observations ("
                "fingerprint BLOB NOT NULL, label TEXT NOT NULL, "
                "file_index INTEGER NOT NULL, line_number INTEGER NOT NULL)"
            )
            with connection:
                for file_index, path in enumerate(paths):
                    with path.open("rb") as handle:
                        raw_header = handle.readline()
                        if not raw_header:
                            raise ValueError(f"CSV is empty: {path}")
                        header = decode_csv_line(raw_header, first_line=True)
                        label_index, indices, duplicate_pair = feature_columns(header)
                        if reference_header is None:
                            reference_header = [name.strip() for name in header]
                        elif [name.strip() for name in header] != reference_header:
                            raise ValueError(f"Schema differs from the first CSV: {path}")

                        batch: list[tuple[bytes, str, int, int]] = []
                        for line_number, raw_line in enumerate(handle, start=2):
                            row = decode_csv_line(raw_line)
                            if len(row) != len(header):
                                raise ValueError(f"Malformed row: {path}:{line_number}")
                            left, right = duplicate_pair
                            if row[left] != row[right]:
                                raise ValueError(
                                    f"Fwd Header Length copies differ: {path}:{line_number}"
                                )
                            batch.append(
                                (feature_hash(row, indices), row[label_index], file_index, line_number)
                            )
                            total_rows += 1
                            if len(batch) == 10_000:
                                connection.executemany(
                                    "INSERT INTO observations VALUES (?, ?, ?, ?)", batch
                                )
                                batch.clear()
                        if batch:
                            connection.executemany(
                                "INSERT INTO observations VALUES (?, ?, ?, ?)", batch
                            )

            connection.execute("CREATE INDEX observations_hash ON observations(fingerprint)")
            summary = summarize_groups(connection, files, details)
        finally:
            connection.close()

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": {
            "feature_fingerprint": "SHA-256 of JSON-serialized CSV cell strings",
            "excluded_columns": ["Label", "second Fwd Header Length"],
            "comparison": "exact feature-cell strings; not near-duplicate or numeric equivalence",
            "line_numbers": "one-based physical CSV lines, including the header",
            "cross_file": "different CSV files; no temporal order is inferred",
        },
        "file_count": len(paths),
        "total_rows": total_rows,
        **summary,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="CSV paths or glob patterns")
    parser.add_argument("--output", type=Path, help="Write summary JSON to this path")
    parser.add_argument(
        "--groups-output", type=Path, help="Write all repeated groups as JSONL"
    )
    args = parser.parse_args()
    if args.output is not None and args.output == args.groups_output:
        parser.error("--output and --groups-output must be different paths")

    try:
        paths = expand_inputs(args.inputs)
        if args.groups_output is None:
            report = audit_feature_leakage(paths, Path.cwd().resolve())
        else:
            args.groups_output.parent.mkdir(parents=True, exist_ok=True)
            with args.groups_output.open("w", encoding="utf-8", newline="\n") as details:
                report = audit_feature_leakage(paths, Path.cwd().resolve(), details)
            report["groups_output"] = args.groups_output.as_posix()
    except (FileNotFoundError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None

    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
