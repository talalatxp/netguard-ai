"""Tests for the AI-10 local inference contract."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from inference import (  # noqa: E402
    FrozenModelSpec,
    InputValidationError,
    load_model_specs,
    load_verified_model,
    predict_rows,
    prepare_input_frame,
    project_root,
)
from train_baselines import file_sha256  # noqa: E402


class FixedProbabilityModel:
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        attack = np.asarray(features["A"], dtype=float)
        return np.column_stack([1.0 - attack, attack])


class InputContractTests(unittest.TestCase):
    def test_orders_features_and_ignores_optional_label(self) -> None:
        frame = pd.DataFrame({" B ": [2], "Label": ["BENIGN"], " A": [1]})

        result = prepare_input_frame(frame, ("A", "B"))

        self.assertEqual(list(result.columns), ["A", "B"])
        self.assertEqual(result.iloc[0].tolist(), [1, 2])

    def test_rejects_the_complete_batch_when_a_value_is_not_numeric(self) -> None:
        frame = pd.DataFrame({"A": [1, "broken"], "B": [2, 3]})

        with self.assertRaisesRegex(InputValidationError, "batch was not scored"):
            prepare_input_frame(frame, ("A", "B"))

    def test_reports_missing_and_unexpected_columns(self) -> None:
        frame = pd.DataFrame({"A": [1], "C": [3]})

        with self.assertRaisesRegex(InputValidationError, "missing columns: B"):
            prepare_input_frame(frame, ("A", "B"))
        with self.assertRaisesRegex(InputValidationError, "unexpected columns: C"):
            prepare_input_frame(frame, ("A", "B"))

    def test_prediction_uses_the_frozen_threshold(self) -> None:
        result = predict_rows(
            FixedProbabilityModel(),
            pd.DataFrame({"A": [0.2, 0.8], "B": [1, 1]}),
            threshold=0.7,
        )

        self.assertEqual(result["prediction"].tolist(), ["BENIGN", "ATTACK"])
        self.assertEqual(result["frozen_threshold"].tolist(), [0.7, 0.7])


class FrozenArtifactTests(unittest.TestCase):
    def test_committed_reports_define_all_six_learned_model_options(self) -> None:
        root = project_root()
        specs = load_model_specs(
            root / "reports" / "ai-07-baseline-results.json",
            root / "reports" / "ai-08-model-comparison-results.json",
            root / "reports" / "ai-09-error-analysis.json",
            root,
        )

        self.assertEqual(len(specs), 6)
        self.assertIn("random:hist_gradient_boosting", specs)
        self.assertIn("temporal:logistic_regression_sgd", specs)
        self.assertEqual(len(specs["temporal:random_forest"].important_features), 10)

    def test_loader_rejects_a_changed_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "model.joblib"
            joblib.dump(FixedProbabilityModel(), artifact)
            spec = FrozenModelSpec(
                key="fixture",
                display_name="Fixture",
                evaluation="random",
                model_name="fixture",
                artifact=artifact,
                artifact_sha256="0" * 64,
                threshold=0.5,
                validation_metrics={},
                test_metrics={},
                important_features=(),
                caveat="fixture",
            )

            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_verified_model(spec)

            valid_spec = FrozenModelSpec(
                **{**spec.__dict__, "artifact_sha256": file_sha256(artifact)}
            )
            self.assertIsInstance(load_verified_model(valid_spec), FixedProbabilityModel)


if __name__ == "__main__":
    unittest.main()
