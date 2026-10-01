"""Load model rows from the frozen split manifest."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


EVALUATION_COLUMNS = {
    "random": "random_partition",
    "temporal": "temporal_partition",
}
PARTITIONS = {"train", "validation", "test"}
REQUIRED_COLUMNS = {
    "source_file",
    "line_number",
    "label_canonical",
    "target",
    "feature_hash",
    "temporal_novel",
    *EVALUATION_COLUMNS.values(),
}


@dataclass(frozen=True)
class ManifestSelection:
    source_file: Path
    line_number: int
    target: int
    temporal_novel: bool


@dataclass(frozen=True)
class ManifestRecord:
    source_file: Path
    line_number: int
    label_canonical: str
    target: int
    feature_hash: str
    random_partition: str
    temporal_partition: str
    temporal_novel: bool


def iter_manifest_records(manifest_path: Path) -> Iterator[ManifestRecord]:
    """Yield every validated record from the frozen split manifest."""
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or ())
        missing_columns = sorted(REQUIRED_COLUMNS - fieldnames)
        if missing_columns:
            raise ValueError(
                "split manifest is missing required columns: "
                + ", ".join(missing_columns)
            )

        for manifest_line, row in enumerate(reader, start=2):
            try:
                line_number = int(row["line_number"])
                target = int(row["target"])
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"invalid integer in split manifest line {manifest_line}"
                ) from error

            if line_number < 2:
                raise ValueError(
                    f"invalid source line number in split manifest line {manifest_line}"
                )
            if target not in {0, 1}:
                raise ValueError(
                    f"invalid target in split manifest line {manifest_line}: {target}"
                )

            temporal_novel_value = row["temporal_novel"]
            if temporal_novel_value not in {"0", "1"}:
                raise ValueError(
                    "invalid temporal_novel value in split manifest line "
                    f"{manifest_line}: {temporal_novel_value!r}"
                )

            partitions = {
                column: row[column] for column in EVALUATION_COLUMNS.values()
            }
            for column, value in partitions.items():
                if value not in PARTITIONS:
                    raise ValueError(
                        f"invalid {column} in split manifest line "
                        f"{manifest_line}: {value!r}"
                    )

            source_file = row["source_file"]
            if not source_file:
                raise ValueError(
                    f"empty source_file in split manifest line {manifest_line}"
                )
            label_canonical = row.get("label_canonical", "")
            if not label_canonical:
                raise ValueError(
                    f"empty label_canonical in split manifest line {manifest_line}"
                )
            feature_hash = row.get("feature_hash", "")
            try:
                hash_bytes = bytes.fromhex(feature_hash)
            except ValueError as error:
                raise ValueError(
                    f"invalid feature_hash in split manifest line {manifest_line}"
                ) from error
            if len(hash_bytes) != 32:
                raise ValueError(
                    f"invalid feature_hash in split manifest line {manifest_line}"
                )

            yield ManifestRecord(
                source_file=Path(source_file),
                line_number=line_number,
                label_canonical=label_canonical,
                target=target,
                feature_hash=feature_hash,
                random_partition=partitions["random_partition"],
                temporal_partition=partitions["temporal_partition"],
                temporal_novel=temporal_novel_value == "1",
            )


def iter_manifest_selection(
    manifest_path: Path,
    evaluation: str,
    partition: str,
) -> Iterator[ManifestSelection]:
    """Yield validated row references for one frozen evaluation partition."""
    if evaluation not in EVALUATION_COLUMNS:
        raise ValueError(f"unsupported evaluation: {evaluation!r}")
    if partition not in PARTITIONS:
        raise ValueError(f"unsupported partition: {partition!r}")

    partition_attribute = EVALUATION_COLUMNS[evaluation]
    for record in iter_manifest_records(manifest_path):
        if getattr(record, partition_attribute) == partition:
            yield ManifestSelection(
                source_file=record.source_file,
                line_number=record.line_number,
                target=record.target,
                temporal_novel=record.temporal_novel,
            )


def iter_selected_raw_lines(
    path: Path,
    line_numbers: Iterator[int],
) -> Iterator[tuple[int, bytes]]:
    """Yield requested binary CSV lines without retaining skipped rows."""
    with path.open("rb") as handle:
        if not handle.readline():
            raise ValueError(f"CSV is empty: {path}")
        current_line = 1
        for requested_line in line_numbers:
            if requested_line < 2:
                raise ValueError("source line numbers must be at least 2")
            if requested_line <= current_line:
                raise ValueError("source line numbers must be strictly increasing")
            while current_line < requested_line:
                raw_line = handle.readline()
                if not raw_line:
                    raise ValueError(
                        f"source line {requested_line} is past end of file: {path}"
                    )
                current_line += 1
            yield requested_line, raw_line
