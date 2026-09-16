"""Tests for the compact model-matrix builder."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from audit_feature_leakage import feature_hash  # noqa: E402
from build_model_matrix import build_model_matrix  # noqa: E402


class BuildModelMatrixTests(unittest.TestCase):
    HEADER = [
        " Destination Port",
        " Fwd Header Length",
        " Fwd Header Length",
        " Label",
    ]
    FEATURE_INDICES = [0, 1]

    def test_builds_aligned_compact_arrays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.csv"
            rows = [["80", "12", "12", "BENIGN"], ["22", "9", "9", "Bot"]]
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.HEADER)
                writer.writerows(rows)

            manifest = root / "manifest.csv"
            with manifest.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "source_file",
                        "line_number",
                        "label_raw",
                        "label_canonical",
                        "target",
                        "feature_hash",
                        "random_partition",
                        "temporal_partition",
                        "temporal_novel",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "source_file": "source.csv",
                        "line_number": 2,
                        "label_raw": "BENIGN",
                        "label_canonical": "BENIGN",
                        "target": 0,
                        "feature_hash": feature_hash(rows[0], self.FEATURE_INDICES).hex(),
                        "random_partition": "train",
                        "temporal_partition": "train",
                        "temporal_novel": 1,
                    }
                )
                writer.writerow(
                    {
                        "source_file": "source.csv",
                        "line_number": 3,
                        "label_raw": "Bot",
                        "label_canonical": "Bot",
                        "target": 1,
                        "feature_hash": feature_hash(rows[1], self.FEATURE_INDICES).hex(),
                        "random_partition": "test",
                        "temporal_partition": "validation",
                        "temporal_novel": 0,
                    }
                )

            summary = root / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "retained_rows": 2,
                        "feature_count": 2,
                        "feature_names": ["Destination Port", "Fwd Header Length"],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "matrix"

            metadata = build_model_matrix(manifest, summary, root, output)

            features = np.load(output / "features.npy")
            targets = np.load(output / "target.npy")
            random_partition = np.load(output / "random_partition.npy")
            self.assertEqual(metadata["rows"], 2)
            self.assertEqual(features.dtype, np.float32)
            np.testing.assert_array_equal(features, [[80, 12], [22, 9]])
            np.testing.assert_array_equal(targets, [0, 1])
            np.testing.assert_array_equal(random_partition, [0, 2])

    def test_rejects_output_directory_with_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "matrix"
            output.mkdir()
            (output / "existing.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "not empty"):
                build_model_matrix(
                    root / "missing.csv", root / "missing.json", root, output
                )


if __name__ == "__main__":
    unittest.main()
