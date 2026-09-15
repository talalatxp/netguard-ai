"""Tests for deterministic split-assignment helpers."""

from __future__ import annotations

import hashlib
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_splits import partition_from_unit_interval, random_partition  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
