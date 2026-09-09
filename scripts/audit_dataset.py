"""Audit CIC-IDS2017 types, missing values, non-finite values, and duplicates."""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path


def expand_inputs(patterns: list[str]) -> list[Path]:
    matches: set[Path] = set()
    for pattern in patterns:
        expanded = glob.glob(pattern, recursive=True)
        if not expanded:
            raise FileNotFoundError(f"No files matched: {pattern}")
        matches.update(Path(item).resolve() for item in expanded if Path(item).is_file())
    if not matches:
        raise FileNotFoundError("No CSV files were selected")
    return sorted(matches, key=lambda path: path.as_posix().lower())


def display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def decode_csv_line(raw_line: bytes, *, first_line: bool = False) -> list[str]:
    encoding = "utf-8-sig" if first_line else "utf-8"
    text = raw_line.decode(encoding).rstrip("\r\n")
    return next(csv.reader([text]))


def find_label_index(header: list[str]) -> int:
    matches = [
        index for index, column in enumerate(header) if column.strip().lower() == "label"
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one Label column, found {len(matches)}")
    return matches[0]


def new_column_stats(index: int, raw_name: str) -> dict[str, object]:
    return {
        "index": index,
        "raw_name": raw_name,
        "normalized_name": raw_name.strip(),
        "empty_count": 0,
        "numeric_count": 0,
        "finite_count": 0,
        "nan_count": 0,
        "positive_infinity_count": 0,
        "negative_infinity_count": 0,
        "non_numeric_count": 0,
        "finite_min": None,
        "finite_max": None,
        "non_numeric_examples": [],
    }


def update_column_stats(stats: dict[str, object], value: str) -> None:
    stripped = value.strip()
    if not stripped:
        stats["empty_count"] = int(stats["empty_count"]) + 1
        return

    try:
        number = float(stripped)
    except ValueError:
        stats["non_numeric_count"] = int(stats["non_numeric_count"]) + 1
        examples = stats["non_numeric_examples"]
        if stripped not in examples and len(examples) < 5:
            examples.append(stripped)
        return

    stats["numeric_count"] = int(stats["numeric_count"]) + 1
    if math.isnan(number):
        stats["nan_count"] = int(stats["nan_count"]) + 1
    elif math.isinf(number):
        key = "positive_infinity_count" if number > 0 else "negative_infinity_count"
        stats[key] = int(stats[key]) + 1
    else:
        stats["finite_count"] = int(stats["finite_count"]) + 1
        current_min = stats["finite_min"]
        current_max = stats["finite_max"]
        stats["finite_min"] = number if current_min is None else min(current_min, number)
        stats["finite_max"] = number if current_max is None else max(current_max, number)


def infer_type(stats: dict[str, object]) -> str:
    numeric_count = int(stats["numeric_count"])
    non_numeric_count = int(stats["non_numeric_count"])
    if numeric_count and non_numeric_count:
        return "mixed"
    if numeric_count:
        return "numeric"
    if non_numeric_count:
        return "string"
    return "empty"


def audit_files(paths: list[Path], root: Path) -> dict[str, object]:
    reference_header: list[str] | None = None
    column_stats: list[dict[str, object]] = []
    seen_rows: set[bytes] = set()
    duplicate_labels: Counter[str] = Counter()
    duplicate_column_pairs: list[tuple[int, int, str]] = []
    duplicate_column_pair_mismatches: Counter[tuple[int, int]] = Counter()
    file_results: list[dict[str, object]] = []
    total_rows = 0
    malformed_rows = 0

    for path in paths:
        file_seen: set[bytes] = set()
        file_rows = 0
        file_malformed = 0
        within_file_duplicates = 0
        cross_file_duplicates = 0

        with path.open("rb") as file_handle:
            header_line = file_handle.readline()
            if not header_line:
                raise ValueError(f"CSV is empty: {path}")
            header = decode_csv_line(header_line, first_line=True)
            label_index = find_label_index(header)

            if reference_header is None:
                reference_header = header
                column_stats = [
                    new_column_stats(index, name) for index, name in enumerate(header)
                ]
                normalized_positions: dict[str, list[int]] = {}
                for index, name in enumerate(header):
                    normalized_positions.setdefault(name.strip(), []).append(index)
                duplicate_column_pairs = [
                    (left, right, name)
                    for name, positions in normalized_positions.items()
                    for left, right in combinations(positions, 2)
                ]
            elif header != reference_header:
                raise ValueError(f"Schema differs from the first CSV: {path}")

            for raw_line in file_handle:
                file_rows += 1
                total_rows += 1
                row = decode_csv_line(raw_line)
                if len(row) != len(header):
                    file_malformed += 1
                    malformed_rows += 1
                    continue

                for stats, value in zip(column_stats, row, strict=True):
                    update_column_stats(stats, value)

                for left, right, _name in duplicate_column_pairs:
                    if row[left] != row[right]:
                        duplicate_column_pair_mismatches[(left, right)] += 1

                fingerprint = hashlib.sha256(raw_line.rstrip(b"\r\n")).digest()
                label = row[label_index].strip()
                if fingerprint in file_seen:
                    within_file_duplicates += 1
                    duplicate_labels[label] += 1
                elif fingerprint in seen_rows:
                    cross_file_duplicates += 1
                    duplicate_labels[label] += 1
                else:
                    seen_rows.add(fingerprint)
                file_seen.add(fingerprint)

        file_results.append(
            {
                "path": display_path(path, root),
                "row_count": file_rows,
                "malformed_row_count": file_malformed,
                "within_file_duplicate_count": within_file_duplicates,
                "cross_file_duplicate_count": cross_file_duplicates,
            }
        )

    for stats in column_stats:
        stats["inferred_type"] = infer_type(stats)

    normalized_names: Counter[str] = Counter(
        str(stats["normalized_name"]) for stats in column_stats
    )
    duplicate_column_names = {
        name: count for name, count in sorted(normalized_names.items()) if count > 1
    }
    duplicate_rows = total_rows - len(seen_rows) - malformed_rows

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": {
            "numeric_parser": "Python float",
            "duplicate_definition": (
                "identical raw CSV row bytes after removing the line ending"
            ),
            "duplicate_fingerprint": "SHA-256",
        },
        "file_count": len(paths),
        "total_rows": total_rows,
        "malformed_row_count": malformed_rows,
        "unique_well_formed_row_count": len(seen_rows),
        "duplicate_row_count": duplicate_rows,
        "duplicate_rows_by_label": dict(sorted(duplicate_labels.items())),
        "duplicate_normalized_column_names": duplicate_column_names,
        "duplicate_column_comparisons": [
            {
                "normalized_name": name,
                "left_index": left,
                "right_index": right,
                "mismatch_count": duplicate_column_pair_mismatches[(left, right)],
            }
            for left, right, name in duplicate_column_pairs
        ],
        "columns": column_stats,
        "files": file_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit CSV types, empty values, NaN, infinities, and exact duplicates."
        )
    )
    parser.add_argument("inputs", nargs="+", help="CSV paths or glob patterns.")
    parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON to this path instead of standard output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path.cwd().resolve()
    try:
        paths = expand_inputs(args.inputs)
        report = audit_files(paths, root)
    except (FileNotFoundError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None

    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output is None:
        print(rendered, end="")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
