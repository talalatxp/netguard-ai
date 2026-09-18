"""Tests for deterministic AI-15 individual SHAP explanations."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from explain_individual_predictions import (  # noqa: E402
    build_explanations,
    category_indices,
    contribution_records,
    explain_hgb_rows,
    select_score_range_examples,
)


class SelectionTests(unittest.TestCase):
    def test_selects_minimum_median_and_maximum_scores_deterministically(self) -> None:
        scores = np.array([0.5, 0.1, 0.9, 0.3, 0.7])

        selected = select_score_range_examples(np.arange(5), scores)

        self.assertEqual(selected.tolist(), [1, 0, 2])

    def test_category_masks_separate_tp_fp_and_fn(self) -> None:
        targets = np.array([1, 0, 1, 0], dtype=np.uint8)
        predictions = np.array([1, 1, 0, 0], dtype=np.uint8)

        groups = category_indices(targets, predictions)

        self.assertEqual(groups["true_positive"].tolist(), [0])
        self.assertEqual(groups["false_positive"].tolist(), [1])
        self.assertEqual(groups["false_negative"].tolist(), [2])

    def test_contributions_are_sorted_by_direction(self) -> None:
        features = ("a", "b", "c", "d")
        values = np.array([1.0, 2.0, 3.0, 4.0])
        contributions = np.array([0.2, -0.5, 0.7, -0.1])

        attack = contribution_records(features, values, contributions, "toward_attack")
        benign = contribution_records(features, values, contributions, "toward_benign")

        self.assertEqual([item["feature"] for item in attack], ["c", "a"])
        self.assertEqual([item["feature"] for item in benign], ["b", "d"])


class AdditivityTests(unittest.TestCase):
    def test_tree_explanations_reconstruct_hgb_probabilities(self) -> None:
        generator = np.random.default_rng(42)
        frame = pd.DataFrame(
            generator.normal(size=(200, 3)), columns=["a", "b", "c"]
        )
        targets = np.asarray(frame["a"] + frame["b"] > 0, dtype=np.uint8)
        model = Pipeline(
            [
                ("identity", FunctionTransformer(validate=False)),
                ("classifier", HistGradientBoostingClassifier(random_state=42)),
            ]
        ).fit(frame, targets)

        result = explain_hgb_rows(model, frame.iloc[:5])

        self.assertLessEqual(float(result["absolute_errors"].max()), 1e-10)
        self.assertEqual(result["values"].shape, (5, 3))

    def test_report_refuses_to_overwrite_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("frozen", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                build_explanations(
                    Path(directory) / "matrix",
                    Path(directory) / "ai08.json",
                    Path(directory) / "ai09.json",
                    output,
                )


if __name__ == "__main__":
    unittest.main()
