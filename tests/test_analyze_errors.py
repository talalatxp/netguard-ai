"""Tests for the frozen AI-09 descriptive-analysis helpers."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from analyze_errors import (  # noqa: E402
    balanced_sample_indices,
    breakdown_by_code,
    build_analysis,
    grouped_error_metrics,
    permutation_feature_importance,
    score_distribution,
    stable_seed,
)


class ScoreDistributionTests(unittest.TestCase):
    def test_reports_fixed_quantiles(self) -> None:
        result = score_distribution(np.array([0.0, 0.25, 0.5, 0.75, 1.0]))

        self.assertEqual(result["rows"], 5)
        self.assertEqual(result["mean"], 0.5)
        self.assertEqual(result["quantiles"]["q50"], 0.5)

    def test_reports_threshold_errors_by_true_class(self) -> None:
        result = grouped_error_metrics(
            np.array([0, 0, 1, 1], dtype=np.uint8),
            np.array([0.1, 0.9, 0.2, 0.8]),
            0.5,
        )

        self.assertEqual(result["false_positive_count"], 1)
        self.assertEqual(result["false_negative_count"], 1)
        self.assertEqual(result["false_positive_scores"]["rows"], 1)
        self.assertEqual(result["false_negative_scores"]["rows"], 1)

    def test_breakdown_keeps_each_group_independent(self) -> None:
        result = breakdown_by_code(
            np.array([0, 0, 1, 1], dtype=np.uint8),
            {0: "first", 1: "second"},
            np.array([0, 1, 0, 1], dtype=np.uint8),
            np.array([0.1, 0.9, 0.8, 0.2]),
            0.5,
        )

        self.assertEqual(result[0]["true_positive"], 1)
        self.assertEqual(result[0]["false_positive"], 0)
        self.assertEqual(result[1]["false_negative"], 1)
        self.assertEqual(result[1]["false_positive"], 1)


class DeterminismTests(unittest.TestCase):
    def test_balanced_sample_is_deterministic_and_class_balanced(self) -> None:
        targets = np.array([0] * 20 + [1] * 8, dtype=np.uint8)

        first = balanced_sample_indices(targets, 5, 42)
        second = balanced_sample_indices(targets, 5, 42)

        np.testing.assert_array_equal(first, second)
        self.assertEqual(np.count_nonzero(targets[first] == 0), 5)
        self.assertEqual(np.count_nonzero(targets[first] == 1), 5)

    def test_stable_seed_does_not_use_process_hash_randomization(self) -> None:
        self.assertEqual(
            stable_seed(42, "temporal", "feature"),
            stable_seed(42, "temporal", "feature"),
        )
        self.assertNotEqual(stable_seed(42, "random"), stable_seed(42, "temporal"))

    def test_permutation_importance_ranks_a_predictive_feature_first(self) -> None:
        generator = np.random.default_rng(42)
        signal = np.concatenate([np.zeros(100), np.ones(100)])
        frame = pd.DataFrame(
            {"signal": signal, "noise": generator.normal(size=200)}
        )
        targets = signal.astype(np.uint8)
        model = LogisticRegression(random_state=42).fit(frame, targets)

        result = permutation_feature_importance(
            model, frame, targets, "random", "fixture", repeats=2
        )

        self.assertEqual(result["features"][0]["feature"], "signal")
        self.assertGreater(result["features"][0]["mean_pr_auc_drop"], 0.0)

    def test_analysis_refuses_to_overwrite_a_completed_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "analysis.json"
            output.write_text("frozen", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                build_analysis(
                    Path(directory) / "matrix",
                    Path(directory) / "ai07.json",
                    Path(directory) / "ai08.json",
                    output,
                )


if __name__ == "__main__":
    unittest.main()
