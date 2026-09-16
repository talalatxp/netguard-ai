"""Tests for selecting model rows from the frozen split manifest."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from model_data import (  # noqa: E402
    ManifestSelection,
    iter_manifest_selection,
    iter_selected_raw_lines,
)


class ManifestSelectionTests(unittest.TestCase):
    FIELDNAMES = [
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

    def write_manifest(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def row(**overrides: str) -> dict[str, str]:
        values = {
            "source_file": "data/raw/Monday.csv",
            "line_number": "2",
            "label_raw": "BENIGN",
            "label_canonical": "BENIGN",
            "target": "0",
            "feature_hash": "00" * 32,
            "random_partition": "train",
            "temporal_partition": "train",
            "temporal_novel": "1",
        }
        values.update(overrides)
        return values

    def test_selects_requested_partition_in_manifest_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.csv"
            self.write_manifest(
                manifest,
                [
                    self.row(line_number="2", random_partition="train"),
                    self.row(line_number="3", random_partition="validation"),
                    self.row(
                        source_file="data/raw/Tuesday.csv",
                        line_number="4",
                        target="1",
                        random_partition="train",
                        temporal_novel="0",
                    ),
                ],
            )

            selected = list(iter_manifest_selection(manifest, "random", "train"))

        self.assertEqual(
            selected,
            [
                ManifestSelection(Path("data/raw/Monday.csv"), 2, 0, True),
                ManifestSelection(Path("data/raw/Tuesday.csv"), 4, 1, False),
            ],
        )

    def test_uses_the_partition_column_for_the_requested_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.csv"
            self.write_manifest(
                manifest,
                [
                    self.row(
                        random_partition="test",
                        temporal_partition="validation",
                    )
                ],
            )

            temporal = list(
                iter_manifest_selection(manifest, "temporal", "validation")
            )
            random = list(iter_manifest_selection(manifest, "random", "validation"))

        self.assertEqual(len(temporal), 1)
        self.assertEqual(random, [])

    def test_rejects_unknown_evaluation_or_partition(self) -> None:
        missing = Path("does-not-need-to-exist.csv")
        cases = (("unknown", "train"), ("random", "development"))
        for evaluation, partition in cases:
            with self.subTest(evaluation=evaluation, partition=partition):
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    list(iter_manifest_selection(missing, evaluation, partition))

    def test_rejects_missing_required_columns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.csv"
            with manifest.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["source_file"])
                writer.writeheader()

            with self.assertRaisesRegex(ValueError, "missing required columns"):
                list(iter_manifest_selection(manifest, "random", "train"))

    def test_rejects_invalid_manifest_values(self) -> None:
        cases = (
            ({"line_number": "1"}, "source line number"),
            ({"target": "2"}, "invalid target"),
            ({"temporal_novel": "yes"}, "temporal_novel"),
            ({"random_partition": "development"}, "random_partition"),
            ({"source_file": ""}, "empty source_file"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                with tempfile.TemporaryDirectory() as directory:
                    manifest = Path(directory) / "manifest.csv"
                    self.write_manifest(manifest, [self.row(**overrides)])
                    with self.assertRaisesRegex(ValueError, message):
                        list(iter_manifest_selection(manifest, "random", "train"))


class SelectedRawLinesTests(unittest.TestCase):
    def write_source(self, path: Path) -> None:
        path.write_bytes(b"header\nrow-2\nrow-3\nrow-4\n")

    def test_yields_only_requested_lines_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.csv"
            self.write_source(source)

            rows = list(iter_selected_raw_lines(source, iter([2, 4])))

        self.assertEqual(rows, [(2, b"row-2\n"), (4, b"row-4\n")])

    def test_rejects_invalid_or_unordered_line_numbers(self) -> None:
        cases = ([1], [3, 3], [4, 2])
        for line_numbers in cases:
            with self.subTest(line_numbers=line_numbers):
                with tempfile.TemporaryDirectory() as directory:
                    source = Path(directory) / "source.csv"
                    self.write_source(source)
                    with self.assertRaisesRegex(ValueError, "line numbers"):
                        list(iter_selected_raw_lines(source, iter(line_numbers)))

    def test_rejects_a_line_past_end_of_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.csv"
            self.write_source(source)
            with self.assertRaisesRegex(ValueError, "past end of file"):
                list(iter_selected_raw_lines(source, iter([5])))

    def test_rejects_an_empty_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.csv"
            source.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                list(iter_selected_raw_lines(source, iter([2])))


if __name__ == "__main__":
    unittest.main()
