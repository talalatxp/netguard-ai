"""Tests for threshold selection and baseline metrics."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from train_baselines import (  # noqa: E402
    attack_recall_by_training_coverage,
    classification_metrics,
    evaluate_frozen_test,
    select_threshold,
)


class ThresholdSelectionTests(unittest.TestCase):
    def test_maximizes_precision_after_enforcing_recall(self) -> None:
        targets = np.array([1, 1, 1, 1, 1, 0, 0, 0], dtype=np.uint8)
        scores = np.array([0.9, 0.8, 0.7, 0.6, 0.1, 0.65, 0.2, 0.05])

        selected = select_threshold(targets, scores, minimum_recall=0.8)

        self.assertTrue(selected["constraint_met"])
        self.assertGreaterEqual(selected["recall"], 0.8)
        self.assertAlmostEqual(selected["threshold"], 0.6)

    def test_reports_metrics_at_the_frozen_threshold(self) -> None:
        targets = np.array([0, 0, 1, 1], dtype=np.uint8)
        scores = np.array([0.1, 0.8, 0.7, 0.9])

        metrics = classification_metrics(targets, scores, threshold=0.5)

        self.assertEqual(metrics["false_positive_count"], 1)
        self.assertEqual(metrics["confusion_matrix"]["true_positive"], 2)
        self.assertAlmostEqual(metrics["attack_recall"], 1.0)

    def test_separates_seen_and_unseen_attack_recall(self) -> None:
        targets = np.array([1, 1, 1, 0], dtype=np.uint8)
        scores = np.array([0.9, 0.1, 0.8, 0.2])
        labels = np.array([2, 2, 3, 0], dtype=np.uint8)

        results = attack_recall_by_training_coverage(
            targets, scores, 0.5, labels, {2}
        )

        self.assertAlmostEqual(results["seen_in_training"]["attack_recall"], 0.5)
        self.assertAlmostEqual(results["unseen_in_training"]["attack_recall"], 1.0)

    def test_refuses_to_overwrite_a_final_test_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            output.write_text("frozen", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "already exists"):
                evaluate_frozen_test(
                    Path(directory) / "missing-matrix",
                    Path(directory) / "missing-validation.json",
                    output,
                )


if __name__ == "__main__":
    unittest.main()
