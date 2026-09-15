"""Tests for leakage-safe preprocessing helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from preprocessing import (  # noqa: E402
    build_logistic_preprocessor,
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


if __name__ == "__main__":
    unittest.main()
