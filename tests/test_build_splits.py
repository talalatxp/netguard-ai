"""Tests for deterministic split-assignment helpers."""

from __future__ import annotations

import csv
import hashlib
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_splits import (  # noqa: E402
    build_split_manifest,
    chronological_paths,
    normalize_label,
    partition_from_unit_interval,
    random_partition,
    temporal_partition,
    validate_complete_file_set,
)


class PartitionFromUnitIntervalTests(unittest.TestCase):
    def test_frozen_boundaries(self) -> None:
        cases = {
            0.0: "train",
            0.699999: "train",
            0.70: "validation",
            0.849999: "validation",
            0.85: "test",
            0.999999: "test",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(partition_from_unit_interval(value), expected)

    def test_rejects_values_outside_half_open_interval(self) -> None:
        for value in (-0.1, 1.0):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, r"\[0, 1\)"):
                    partition_from_unit_interval(value)


class RandomPartitionTests(unittest.TestCase):
    HASH_A = "00" * 32
    HASH_B = "ff" * 32

    def test_assignment_is_reproducible(self) -> None:
        first = random_partition(self.HASH_A, seed=42)
        self.assertEqual(random_partition(self.HASH_A, seed=42), first)

    def test_frozen_examples_cover_every_partition(self) -> None:
        examples = {
            "0": "train",
            "3": "validation",
            "19": "test",
        }
        for source, expected in examples.items():
            feature_hash = hashlib.sha256(source.encode("ascii")).hexdigest()
            with self.subTest(source=source):
                self.assertEqual(random_partition(feature_hash, seed=42), expected)

    def test_assignment_depends_on_seed_and_feature_hash(self) -> None:
        assignments = {
            random_partition(feature_hash, seed)
            for feature_hash in (self.HASH_A, self.HASH_B)
            for seed in (1, 42, 100)
        }
        self.assertGreater(len(assignments), 1)

    def test_returns_only_frozen_partition_names(self) -> None:
        self.assertIn(
            random_partition(self.HASH_B), {"train", "validation", "test"}
        )

    def test_many_groups_approximately_follow_target_fractions(self) -> None:
        assignments = Counter(
            random_partition(hashlib.sha256(str(index).encode("ascii")).hexdigest())
            for index in range(10_000)
        )
        self.assertTrue(6_800 <= assignments["train"] <= 7_200)
        self.assertTrue(1_300 <= assignments["validation"] <= 1_700)
        self.assertTrue(1_300 <= assignments["test"] <= 1_700)

    def test_rejects_non_hexadecimal_or_wrong_length_hashes(self) -> None:
        for feature_hash in ("not-a-hash", "00" * 31, "00" * 33):
            with self.subTest(feature_hash=feature_hash):
                with self.assertRaisesRegex(ValueError, "feature_hash"):
                    random_partition(feature_hash)


class TemporalPartitionTests(unittest.TestCase):
    def test_assigns_all_verified_dataset_files(self) -> None:
        cases = {
            "Monday-WorkingHours.pcap_ISCX.csv": "train",
            "Tuesday-WorkingHours.pcap_ISCX.csv": "train",
            "Wednesday-workingHours.pcap_ISCX.csv": "train",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "validation",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "validation",
            "Friday-WorkingHours-Morning.pcap_ISCX.csv": "test",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "test",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "test",
        }
        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                self.assertEqual(temporal_partition(Path(filename)), expected)

    def test_rejects_unknown_day(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            temporal_partition(Path("Saturday-WorkingHours.csv"))

    def test_rejects_filename_without_day_separator(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            temporal_partition(Path("Monday.csv"))


class ManifestBuildTests(unittest.TestCase):
    HEADER = [
        " Fwd Header Length",
        " Destination Port",
        " Fwd Header Length",
        " Label",
    ]

    @staticmethod
    def write_source(path: Path, rows: list[list[str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(ManifestBuildTests.HEADER)
            writer.writerows(rows)

    def test_chronological_paths_do_not_use_input_or_alphabetical_order(self) -> None:
        paths = [
            Path("Friday-WorkingHours-Morning.pcap_ISCX.csv"),
            Path("Monday-WorkingHours.pcap_ISCX.csv"),
            Path("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"),
        ]
        ordered = chronological_paths(paths)
        self.assertEqual(
            [path.name for path in ordered],
            [
                "Monday-WorkingHours.pcap_ISCX.csv",
                "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
                "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            ],
        )

    def test_complete_file_validation_rejects_a_partial_snapshot(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_complete_file_set([Path("Monday-WorkingHours.pcap_ISCX.csv")])

    def test_label_normalization_preserves_binary_meaning(self) -> None:
        self.assertEqual(normalize_label(" BENIGN "), ("BENIGN", 0))
        self.assertEqual(
            normalize_label("Web Attack � XSS"), ("Web Attack - XSS", 1)
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            normalize_label("NEW-ATTACK")

    def test_manifest_deduplicates_and_marks_temporal_novelty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            monday = root / "Monday-WorkingHours.pcap_ISCX.csv"
            tuesday = root / "Tuesday-WorkingHours.pcap_ISCX.csv"
            thursday = (
                root / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
            )
            friday = root / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
            self.write_source(
                monday,
                [["1", "80", "1", "BENIGN"], ["2", "22", "2", "FTP-Patator"]],
            )
            self.write_source(
                tuesday,
                [["1", "80", "1", "BENIGN"], ["1", "80", "1", "PortScan"]],
            )
            self.write_source(
                thursday, [["3", "443", "3", "Web Attack � XSS"]]
            )
            self.write_source(
                friday,
                [
                    ["3", "443", "3", "Web Attack � XSS"],
                    ["3", "443", "3", "Bot"],
                    ["4", "53", "4", "BENIGN"],
                ],
            )
            manifest = root / "manifest.csv"
            report = build_split_manifest(
                [friday, thursday, tuesday, monday], root, manifest
            )

            self.assertEqual(report["raw_rows"], 8)
            self.assertEqual(report["retained_rows"], 6)
            self.assertEqual(report["exact_duplicates_removed"], 2)
            self.assertEqual(report["feature_count"], 2)
            self.assertEqual(report["random"]["shared_feature_hash_groups"], 0)
            self.assertEqual(report["temporal"]["test_hashes_seen_earlier"], 1)
            self.assertEqual(report["temporal"]["test_rows_seen_earlier"], 1)
            self.assertEqual(report["conflicting_binary_target_groups"], 1)
            self.assertEqual(report["rows_in_conflicting_binary_target_groups"], 2)

            with manifest.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 6)
            self.assertEqual(Path(rows[0]["source_file"]).name, monday.name)
            self.assertEqual(Path(rows[-1]["source_file"]).name, friday.name)

            groups: dict[str, list[dict[str, str]]] = {}
            for row in rows:
                groups.setdefault(row["feature_hash"], []).append(row)
            repeated_random_groups = [group for group in groups.values() if len(group) > 1]
            self.assertTrue(repeated_random_groups)
            for group in repeated_random_groups:
                self.assertEqual(len({row["random_partition"] for row in group}), 1)

            friday_bot = next(row for row in rows if row["label_canonical"] == "Bot")
            friday_benign = next(
                row
                for row in rows
                if row["temporal_partition"] == "test"
                and row["label_canonical"] == "BENIGN"
            )
            self.assertEqual(friday_bot["temporal_novel"], "0")
            self.assertEqual(friday_benign["temporal_novel"], "1")


if __name__ == "__main__":
    unittest.main()
