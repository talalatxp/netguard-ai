"""Small deterministic checks for the feature-only leakage audit."""

from __future__ import annotations

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from audit_feature_leakage import audit_feature_leakage  # noqa: E402


HEADER = [" Fwd Header Length", "Destination Port", "Fwd Header Length", " Label"]


def write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(rows)


class FeatureLeakageAuditTests(unittest.TestCase):
    def test_repeats_conflicts_and_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a.csv", root / "b.csv"
            write_csv(
                first,
                [
                    ["4", "80", "4", "BENIGN"],
                    ["4", "80", "4", "BENIGN"],
                    ["8", "443", "8", "BENIGN"],
                ],
            )
            write_csv(
                second,
                [
                    ["4", "80", "4", "ATTACK"],
                    ["8", "443", "8", "BENIGN"],
                    ["8", "22", "8", "ATTACK"],
                ],
            )
            details = io.StringIO()
            report = audit_feature_leakage([first, second], root, details)

            self.assertEqual(report["total_rows"], 6)
            self.assertEqual(report["repeated_feature_groups"], 2)
            self.assertEqual(report["repeated_feature_rows"], 5)
            self.assertEqual(report["same_label_groups"], 1)
            self.assertEqual(report["same_label_rows"], 2)
            self.assertEqual(report["conflicting_label_groups"], 1)
            self.assertEqual(report["conflicting_label_rows"], 3)
            self.assertEqual(report["cross_file_groups"], 2)
            self.assertEqual(len(details.getvalue().splitlines()), 2)
            conflict = report["examples"]["conflicting_labels"][0]
            self.assertEqual(conflict["label_counts"], {"ATTACK": 1, "BENIGN": 2})
            self.assertEqual(
                conflict["locations"],
                [
                    {"file": "a.csv", "line": 2},
                    {"file": "a.csv", "line": 3},
                    {"file": "b.csv", "line": 2},
                ],
            )

    def test_mismatched_duplicate_column_stops_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.csv"
            write_csv(path, [["4", "80", "5", "BENIGN"]])
            with self.assertRaisesRegex(ValueError, "copies differ"):
                audit_feature_leakage([path], root)

    def test_malformed_row_stops_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.csv"
            write_csv(path, [["4", "80", "4"]])
            with self.assertRaisesRegex(ValueError, "Malformed row"):
                audit_feature_leakage([path], root)


if __name__ == "__main__":
    unittest.main()
