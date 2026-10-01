"""Tests for the AI-08 tree-model comparison contract."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from train_tree_models import (  # noqa: E402
    choose_validation_winner,
    evaluate_frozen_tree_test,
    model_configuration,
)


class TreeModelContractTests(unittest.TestCase):
    @staticmethod
    def result(precision: float, pr_auc: float, f1: float) -> dict[str, object]:
        return {
            "threshold_selection": {"constraint_met": True},
            "validation": {
                "attack_precision": precision,
                "pr_auc": pr_auc,
                "attack_f1": f1,
            },
        }

    def test_selects_validation_winner_without_test_metrics(self) -> None:
        models = {
            "forest": self.result(0.8, 0.9, 0.7),
            "boosting": self.result(0.85, 0.8, 0.75),
        }

        self.assertEqual(choose_validation_winner(models), "boosting")

    def test_excludes_models_that_miss_the_recall_constraint(self) -> None:
        disqualified = self.result(0.99, 0.99, 0.99)
        disqualified["threshold_selection"]["constraint_met"] = False
        models = {
            "disqualified": disqualified,
            "qualified": self.result(0.5, 0.6, 0.4),
        }

        self.assertEqual(choose_validation_winner(models), "qualified")

    def test_frozen_configurations_keep_seed_and_resource_limits(self) -> None:
        forest = model_configuration("random_forest")
        boosting = model_configuration("hist_gradient_boosting")

        self.assertEqual(forest["n_estimators"], 80)
        self.assertEqual(forest["n_jobs"], 2)
        self.assertEqual(forest["random_state"], 42)
        self.assertEqual(boosting["max_iter"], 150)
        self.assertEqual(boosting["random_state"], 42)

    def test_refuses_to_overwrite_final_tree_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            output.write_text("frozen", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                evaluate_frozen_tree_test(
                    Path(directory) / "missing-matrix",
                    Path(directory) / "missing-validation.json",
                    output,
                )


if __name__ == "__main__":
    unittest.main()
