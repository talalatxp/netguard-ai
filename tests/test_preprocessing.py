"""Tests for leakage-safe preprocessing helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from preprocessing import (  # noqa: E402
    build_hist_gradient_boosting_baseline,
    build_logistic_baseline,
    build_logistic_preprocessor,
    build_random_forest_baseline,
    build_tree_preprocessor,
    replace_non_finite_values,
)


class ReplaceNonFiniteValuesTests(unittest.TestCase):
    def test_replaces_infinities_and_marks_every_non_finite_value(self) -> None:
        frame = pd.DataFrame(
            {
                "Flow Bytes/s": [10.0, np.nan, np.inf, -np.inf],
                "Flow Packets/s": [np.inf, 20.0, np.nan, -30.0],
                "Destination Port": [80, 443, 22, 53],
            }
        )

        transformed = replace_non_finite_values(frame)

        self.assertEqual(
            transformed["Flow Bytes/s__missing"].tolist(), [0, 1, 1, 1]
        )
        self.assertEqual(
            transformed["Flow Packets/s__missing"].tolist(), [1, 0, 1, 0]
        )
        self.assertFalse(
            np.isinf(transformed[["Flow Bytes/s", "Flow Packets/s"]]).any().any()
        )
        self.assertEqual(transformed["Destination Port"].tolist(), [80, 443, 22, 53])

    def test_does_not_modify_the_input_frame(self) -> None:
        frame = pd.DataFrame(
            {
                "Flow Bytes/s": [np.inf],
                "Flow Packets/s": [1.0],
            }
        )

        replace_non_finite_values(frame)

        self.assertTrue(np.isposinf(frame.loc[0, "Flow Bytes/s"]))
        self.assertNotIn("Flow Bytes/s__missing", frame)

    def test_rejects_a_missing_rate_feature(self) -> None:
        frame = pd.DataFrame({"Flow Bytes/s": [1.0]})

        with self.assertRaisesRegex(ValueError, "Flow Packets/s"):
            replace_non_finite_values(frame)


class BuildLogisticPreprocessorTests(unittest.TestCase):
    def test_builds_independent_unfitted_pipelines(self) -> None:
        first = build_logistic_preprocessor()
        second = build_logistic_preprocessor()

        self.assertIsNot(first, second)
        self.assertEqual(list(first.named_steps), ["non_finite", "imputer", "scaler"])
        self.assertFalse(hasattr(first.named_steps["imputer"], "statistics_"))
        self.assertFalse(hasattr(first.named_steps["scaler"], "mean_"))

    def test_validation_values_do_not_change_train_fitted_statistics(self) -> None:
        train = pd.DataFrame(
            {
                "Flow Bytes/s": [1.0, 3.0, np.inf],
                "Flow Packets/s": [10.0, 30.0, 50.0],
            }
        )
        validation = pd.DataFrame(
            {
                "Flow Bytes/s": [np.inf],
                "Flow Packets/s": [1_000_000.0],
            }
        )
        pipeline = build_logistic_preprocessor()

        pipeline.fit(train)
        train_medians = pipeline.named_steps["imputer"].statistics_.copy()
        transformed_validation = pipeline.transform(validation)

        np.testing.assert_array_equal(train_medians, [2.0, 30.0, 0.0, 0.0])
        np.testing.assert_array_equal(
            pipeline.named_steps["imputer"].statistics_, train_medians
        )
        self.assertEqual(transformed_validation.shape, (1, 4))
        self.assertAlmostEqual(transformed_validation[0, 0], 0.0)

    def test_logistic_baseline_uses_the_frozen_configuration(self) -> None:
        baseline = build_logistic_baseline(seed=42)

        self.assertEqual(
            list(baseline.named_steps),
            ["non_finite", "imputer", "scaler", "classifier"],
        )
        classifier = baseline.named_steps["classifier"]
        self.assertEqual(classifier.loss, "log_loss")
        self.assertEqual(classifier.class_weight, "balanced")
        self.assertEqual(classifier.random_state, 42)

    def test_logistic_baseline_fits_and_returns_attack_probabilities(self) -> None:
        frame = pd.DataFrame(
            {
                "Flow Bytes/s": [1.0, 2.0, np.inf, 4.0, 5.0, 6.0],
                "Flow Packets/s": [1.0, 2.0, 3.0, 4.0, np.nan, 6.0],
            }
        )
        targets = np.array([0, 0, 0, 1, 1, 1], dtype=np.uint8)
        baseline = build_logistic_baseline(seed=42)

        baseline.fit(frame, targets)
        probabilities = baseline.predict_proba(frame)

        self.assertEqual(probabilities.shape, (6, 2))
        np.testing.assert_allclose(probabilities.sum(axis=1), 1.0)


class BuildTreePreprocessorTests(unittest.TestCase):
    def test_tree_preprocessor_imputes_without_scaling(self) -> None:
        preprocessor = build_tree_preprocessor()

        self.assertEqual(list(preprocessor.named_steps), ["non_finite", "imputer"])
        self.assertNotIn("scaler", preprocessor.named_steps)

    def test_tree_models_use_the_frozen_resource_aware_configuration(self) -> None:
        forest = build_random_forest_baseline(seed=42).named_steps["classifier"]
        boosting = build_hist_gradient_boosting_baseline(seed=42).named_steps[
            "classifier"
        ]

        self.assertEqual(forest.n_estimators, 80)
        self.assertEqual(forest.max_depth, 18)
        self.assertEqual(forest.max_samples, 0.35)
        self.assertEqual(forest.random_state, 42)
        self.assertEqual(boosting.max_iter, 150)
        self.assertEqual(boosting.max_leaf_nodes, 31)
        self.assertTrue(boosting.early_stopping)
        self.assertEqual(boosting.random_state, 42)

    def test_tree_models_fit_and_return_attack_probabilities(self) -> None:
        bytes_per_second = np.arange(1, 41, dtype=float)
        packets_per_second = np.repeat(np.arange(1, 21, dtype=float), 2)
        bytes_per_second[10] = np.inf
        packets_per_second[30] = np.nan
        frame = pd.DataFrame(
            {
                "Flow Bytes/s": bytes_per_second,
                "Flow Packets/s": packets_per_second,
            }
        )
        targets = np.array([0] * 20 + [1] * 20, dtype=np.uint8)

        for builder in (
            build_random_forest_baseline,
            build_hist_gradient_boosting_baseline,
        ):
            with self.subTest(builder=builder.__name__):
                model = builder(seed=42)
                model.fit(frame, targets)
                probabilities = model.predict_proba(frame)
                self.assertEqual(probabilities.shape, (40, 2))
                np.testing.assert_allclose(probabilities.sum(axis=1), 1.0)


if __name__ == "__main__":
    unittest.main()
