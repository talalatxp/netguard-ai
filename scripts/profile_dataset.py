"""Profile CIC-IDS2017 CSV schemas, row counts, and labels without loading them into memory."""

from __future__ import annotations

import argparse
import csv
import glob
import json
from collections import Counter
from datetime import datetime, timezone
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


def find_label_index(header: list[str]) -> int:
    matches = [
        index for index, column in enumerate(header) if column.strip().lower() == "label"
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one Label column, found {len(matches)}")
    return matches[0]


def profile_file(path: Path, root: Path) -> dict[str, object]:
    labels: Counter[str] = Counter()
    row_count = 0
    malformed_row_count = 0

    with path.open("r", encoding="utf-8-sig", newline="") as file_handle:
        reader = csv.reader(file_handle)
        try:
            header = next(reader)
        except StopIteration as error:
            raise ValueError(f"CSV is empty: {path}") from error

        label_index = find_label_index(header)
        for row in reader:
            row_count += 1
            if len(row) != len(header):
                malformed_row_count += 1
                continue
            labels[row[label_index].strip()] += 1

    return {
        "path": display_path(path, root),
        "size_bytes": path.stat().st_size,
        "row_count": row_count,
        "column_count": len(header),
        "malformed_row_count": malformed_row_count,
        "labels": dict(sorted(labels.items())),
        "columns": header,
    }


def build_report(paths: list[Path], root: Path) -> dict[str, object]:
    profiles = [profile_file(path, root) for path in paths]
    reference_columns = profiles[0]["columns"]
    total_labels: Counter[str] = Counter()

    for profile in profiles:
        total_labels.update(profile["labels"])
        profile["schema_matches_reference"] = profile["columns"] == reference_columns
        del profile["columns"]

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_count": len(profiles),
        "total_rows": sum(int(profile["row_count"]) for profile in profiles),
        "schemas_are_identical": all(
            bool(profile["schema_matches_reference"]) for profile in profiles
        ),
        "column_count": len(reference_columns),
        "columns": reference_columns,
        "labels": dict(sorted(total_labels.items())),
        "files": profiles,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile CSV schemas, row counts, and exact label values."
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
        report = build_report(paths, root)
    except (FileNotFoundError, ValueError) as error:
        raise SystemExit(f"error: {error}") from None

    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output is None:
        print(rendered, end="")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
