"""Train, freeze, and evaluate the AI-08 tree-model comparison."""

from __future__ import annotations

import argparse
import gc
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import joblib
import numpy as np

from preprocessing import (
    build_hist_gradient_boosting_baseline,
    build_random_forest_baseline,
)
from train_baselines import (
    EVALUATIONS,
    MINIMUM_ATTACK_RECALL,
    SEED,
    ModelMatrix,
    classification_metrics,
    file_sha256,
    probability_scores,
    select_threshold,
    subgroup_metrics,
)


MODEL_BUILDERS: dict[str, Callable[[int], object]] = {
    "random_forest": build_random_forest_baseline,
    "hist_gradient_boosting": build_hist_gradient_boosting_baseline,
}


def model_configuration(model_name: str) -> dict[str, object]:
    if model_name == "random_forest":
        return {
            "n_estimators": 80,
            "max_depth": 18,
            "min_samples_leaf": 20,
            "max_features": "sqrt",
            "bootstrap": True,
            "max_samples": 0.35,
            "class_weight": "balanced_subsample",
            "n_jobs": 2,
            "random_state": SEED,
        }
    if model_name == "hist_gradient_boosting":
        return {
            "loss": "log_loss",
            "learning_rate": 0.08,
            "max_iter": 150,
            "max_leaf_nodes": 31,
            "min_samples_leaf": 50,
            "l2_regularization": 1.0,
            "class_weight": "balanced",
            "early_stopping": True,
            "validation_fraction": 0.1,
            "n_iter_no_change": 15,
            "tol": 1e-7,
            "random_state": SEED,
        }
    raise ValueError(f"unknown tree model: {model_name}")


def choose_validation_winner(models: dict[str, dict[str, object]]) -> str | None:
    """Choose by frozen validation precision, then PR-AUC and F1."""
    qualifying = [
        (name, result)
        for name, result in models.items()
        if result["threshold_selection"]["constraint_met"]
    ]
    if not qualifying:
        return None
    return max(
        qualifying,
        key=lambda item: (
            item[1]["validation"]["attack_precision"],
            item[1]["validation"]["pr_auc"],
            item[1]["validation"]["attack_f1"],
        ),
    )[0]


def fitted_diagnostics(model_name: str, model: object) -> dict[str, object]:
    classifier = model.named_steps["classifier"]
    if model_name == "random_forest":
        return {"fitted_trees": len(classifier.estimators_)}
    return {
        "fitted_iterations": int(classifier.n_iter_),
        "early_stopping_used": bool(classifier.early_stopping),
    }


def train_and_freeze_trees(
    matrix_directory: Path,
    models_directory: Path,
    ai07_results_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"AI-08 validation record already exists: {output_path}")
    models_directory.mkdir(parents=True, exist_ok=True)
    matrix = ModelMatrix(matrix_directory)
    report: dict[str, object] = {
        "stage": "ai_08_validation_frozen_before_test",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "contract": {
            "minimum_attack_recall": MINIMUM_ATTACK_RECALL,
            "threshold_selection": "highest precision among qualifying thresholds",
            "model_comparison": "highest validation precision, then PR-AUC and F1",
            "test_used": False,
        },
        "seed": SEED,
        "matrix_metadata_sha256": file_sha256(matrix.metadata_path),
        "ai_07_results": {
            "path": ai07_results_path.as_posix(),
            "sha256": file_sha256(ai07_results_path),
        },
        "evaluations": {},
    }
    evaluations = report["evaluations"]
    assert isinstance(evaluations, dict)

    for evaluation in EVALUATIONS:
        train_mask = matrix.mask(evaluation, "train")
        validation_mask = matrix.mask(evaluation, "validation")
        train_targets = np.asarray(matrix.target[train_mask], dtype=np.uint8)
        validation_targets = np.asarray(
            matrix.target[validation_mask], dtype=np.uint8
        )
        training_labels = np.asarray(matrix.label_code[train_mask], dtype=np.uint8)
        training_attack_labels = set(
            int(value) for value in np.unique(training_labels[train_targets == 1])
        )
        train_features = matrix.frame(train_mask)
        validation_features = matrix.frame(validation_mask)
        evaluation_result: dict[str, object] = {
            "train_rows": int(train_targets.size),
            "validation_rows": int(validation_targets.size),
            "training_attack_label_codes": sorted(training_attack_labels),
            "models": {},
        }
        models = evaluation_result["models"]
        assert isinstance(models, dict)

        for model_name, builder in MODEL_BUILDERS.items():
            model = builder(SEED)
            started = time.perf_counter()
            model.fit(train_features, train_targets)
            fit_seconds = time.perf_counter() - started
            scores = probability_scores(model, validation_features)
            threshold_selection = select_threshold(validation_targets, scores)
            threshold = float(threshold_selection["threshold"])
            artifact = models_directory / f"{evaluation}-{model_name}.joblib"
            joblib.dump(model, artifact, compress=3)
            models[model_name] = {
                "configuration": model_configuration(model_name),
                "fitted_diagnostics": fitted_diagnostics(model_name, model),
                "fit_seconds": fit_seconds,
                "artifact": artifact.as_posix(),
                "artifact_sha256": file_sha256(artifact),
                "threshold_selection": threshold_selection,
                "validation": classification_metrics(
                    validation_targets, scores, threshold
                ),
                "validation_subgroups": subgroup_metrics(
                    matrix,
                    validation_mask,
                    validation_targets,
                    scores,
                    threshold,
                    training_attack_labels,
                    evaluation,
                ),
            }
            del model, scores
            gc.collect()

        evaluation_result["validation_winner"] = choose_validation_winner(models)
        evaluations[evaluation] = evaluation_result
        del train_features, validation_features, train_mask, validation_mask
        gc.collect()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def evaluate_frozen_tree_test(
    matrix_directory: Path,
    validation_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"AI-08 test result already exists: {output_path}")
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if validation["contract"]["test_used"]:
        raise ValueError("AI-08 validation record already marks test as used")
    matrix = ModelMatrix(matrix_directory)
    if file_sha256(matrix.metadata_path) != validation["matrix_metadata_sha256"]:
        raise ValueError("model matrix differs from frozen AI-08 validation record")

    report: dict[str, object] = {
        "stage": "ai_08_final_test_evaluated_once",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation_record": validation_path.as_posix(),
        "validation_record_sha256_before_test": file_sha256(validation_path),
        "contract": validation["contract"] | {"test_used": True},
        "seed": validation["seed"],
        "matrix_metadata_sha256": validation["matrix_metadata_sha256"],
        "ai_07_results": validation["ai_07_results"],
        "evaluations": {},
    }
    evaluations = report["evaluations"]
    assert isinstance(evaluations, dict)

    for evaluation in EVALUATIONS:
        frozen = validation["evaluations"][evaluation]
        training_attack_labels = set(frozen["training_attack_label_codes"])
        test_mask = matrix.mask(evaluation, "test")
        test_targets = np.asarray(matrix.target[test_mask], dtype=np.uint8)
        test_features = matrix.frame(test_mask)
        evaluation_result: dict[str, object] = {
            "train_rows": frozen["train_rows"],
            "validation_rows": frozen["validation_rows"],
            "test_rows": int(test_targets.size),
            "training_attack_label_codes": sorted(training_attack_labels),
            "validation_winner": frozen["validation_winner"],
            "models": {},
        }
        models = evaluation_result["models"]
        assert isinstance(models, dict)

        for model_name in MODEL_BUILDERS:
            frozen_model = frozen["models"][model_name]
            artifact = Path(frozen_model["artifact"])
            if file_sha256(artifact) != frozen_model["artifact_sha256"]:
                raise ValueError(f"frozen AI-08 model changed: {artifact}")
            model = joblib.load(artifact)
            scores = probability_scores(model, test_features)
            threshold = float(frozen_model["threshold_selection"]["threshold"])
            models[model_name] = {
                **frozen_model,
                "test": classification_metrics(test_targets, scores, threshold),
                "test_subgroups": subgroup_metrics(
                    matrix,
                    test_mask,
                    test_targets,
                    scores,
                    threshold,
                    training_attack_labels,
                    evaluation,
                ),
            }
            del model, scores
            gc.collect()

        evaluations[evaluation] = evaluation_result
        del test_features, test_mask
        gc.collect()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("validation", "test"))
    parser.add_argument(
        "--matrix-dir", type=Path, default=Path("data/processed/model-matrix")
    )
    parser.add_argument("--models-dir", type=Path, default=Path("models/ai-08"))
    parser.add_argument(
        "--ai-07-results",
        type=Path,
        default=Path("reports/ai-07-baseline-results.json"),
    )
    parser.add_argument(
        "--validation-output",
        type=Path,
        default=Path("reports/ai-08-validation.json"),
    )
    parser.add_argument(
        "--test-output",
        type=Path,
        default=Path("reports/ai-08-model-comparison-results.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.stage == "validation":
        report = train_and_freeze_trees(
            args.matrix_dir,
            args.models_dir,
            args.ai_07_results,
            args.validation_output,
        )
    else:
        report = evaluate_frozen_tree_test(
            args.matrix_dir, args.validation_output, args.test_output
        )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
