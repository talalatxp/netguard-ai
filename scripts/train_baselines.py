"""Train, freeze, and evaluate AI-07 baseline models without test leakage."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)

from preprocessing import build_logistic_baseline


EVALUATIONS = ("random", "temporal")
MODEL_NAMES = ("dummy", "logistic_regression_sgd")
MINIMUM_ATTACK_RECALL = 0.80
SEED = 42


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_threshold(
    targets: np.ndarray,
    scores: np.ndarray,
    minimum_recall: float = MINIMUM_ATTACK_RECALL,
) -> dict[str, float | bool]:
    """Maximize precision among thresholds meeting the frozen recall constraint."""
    precision, recall, thresholds = precision_recall_curve(targets, scores)
    candidates = [
        (float(precision[index]), float(threshold), float(recall[index]))
        for index, threshold in enumerate(thresholds)
        if recall[index] >= minimum_recall
    ]
    if not candidates:
        return {
            "constraint_met": False,
            "threshold": 0.5,
            "precision": 0.0,
            "recall": 0.0,
        }
    selected_precision, threshold, selected_recall = max(
        candidates, key=lambda item: (item[0], item[1])
    )
    return {
        "constraint_met": True,
        "threshold": threshold,
        "precision": selected_precision,
        "recall": selected_recall,
    }


def classification_metrics(
    targets: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, object]:
    predictions = (scores >= threshold).astype(np.uint8)
    true_negative, false_positive, false_negative, true_positive = confusion_matrix(
        targets, predictions, labels=[0, 1]
    ).ravel()
    benign_rows = int(true_negative + false_positive)
    return {
        "rows": int(targets.size),
        "attack_rows": int(np.count_nonzero(targets)),
        "threshold": float(threshold),
        "attack_precision": float(
            precision_score(targets, predictions, zero_division=0)
        ),
        "attack_recall": float(recall_score(targets, predictions, zero_division=0)),
        "attack_f1": float(f1_score(targets, predictions, zero_division=0)),
        "pr_auc": float(average_precision_score(targets, scores)),
        "false_positive_rate": (
            float(false_positive / benign_rows) if benign_rows else 0.0
        ),
        "false_positive_count": int(false_positive),
        "confusion_matrix": {
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }


def attack_recall_by_training_coverage(
    targets: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    label_codes: np.ndarray,
    training_attack_labels: set[int],
) -> dict[str, dict[str, object]]:
    predictions = scores >= threshold
    results: dict[str, dict[str, object]] = {}
    for name, label_filter in (
        ("seen_in_training", np.isin(label_codes, list(training_attack_labels))),
        ("unseen_in_training", ~np.isin(label_codes, list(training_attack_labels))),
    ):
        mask = (targets == 1) & label_filter
        rows = int(np.count_nonzero(mask))
        detected = int(np.count_nonzero(predictions[mask]))
        results[name] = {
            "attack_rows": rows,
            "detected_attack_rows": detected,
            "attack_recall": float(detected / rows) if rows else None,
        }
    return results


class ModelMatrix:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.metadata_path = directory / "metadata.json"
        self.metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        self.features = np.load(directory / "features.npy", mmap_mode="r")
        self.target = np.load(directory / "target.npy", mmap_mode="r")
        self.random_partition = np.load(
            directory / "random_partition.npy", mmap_mode="r"
        )
        self.temporal_partition = np.load(
            directory / "temporal_partition.npy", mmap_mode="r"
        )
        self.temporal_novel = np.load(
            directory / "temporal_novel.npy", mmap_mode="r"
        )
        self.label_code = np.load(directory / "label_code.npy", mmap_mode="r")
        rows = int(self.metadata["rows"])
        if self.features.shape != (rows, int(self.metadata["feature_count"])):
            raise ValueError("feature matrix shape differs from metadata")
        for array in (
            self.target,
            self.random_partition,
            self.temporal_partition,
            self.temporal_novel,
            self.label_code,
        ):
            if array.shape != (rows,):
                raise ValueError("model metadata array shape differs from metadata")

    def mask(self, evaluation: str, partition: str) -> np.ndarray:
        code = int(self.metadata["partition_codes"][partition])
        values = getattr(self, f"{evaluation}_partition")
        return np.asarray(values == code)

    def frame(self, mask: np.ndarray) -> pd.DataFrame:
        values = np.asarray(self.features[mask], dtype=np.float32)
        return pd.DataFrame(
            values, columns=list(self.metadata["feature_names"]), copy=False
        )


def probability_scores(model: object, features: object) -> np.ndarray:
    probabilities = model.predict_proba(features)
    return np.asarray(probabilities[:, 1], dtype=np.float64)


def subgroup_metrics(
    matrix: ModelMatrix,
    mask: np.ndarray,
    targets: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    training_attack_labels: set[int],
    evaluation: str,
) -> dict[str, object]:
    labels = np.asarray(matrix.label_code[mask], dtype=np.uint8)
    results: dict[str, object] = {
        "attack_training_coverage": attack_recall_by_training_coverage(
            targets, scores, threshold, labels, training_attack_labels
        )
    }
    if evaluation == "temporal":
        novel = np.asarray(matrix.temporal_novel[mask], dtype=bool)
        results["novel_feature_vectors"] = classification_metrics(
            targets[novel], scores[novel], threshold
        )
    return results


def train_and_freeze(
    matrix_directory: Path,
    models_directory: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"validation record already exists: {output_path}")
    models_directory.mkdir(parents=True, exist_ok=True)
    matrix = ModelMatrix(matrix_directory)
    report: dict[str, object] = {
        "stage": "validation_frozen_before_test",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "contract": {
            "minimum_attack_recall": MINIMUM_ATTACK_RECALL,
            "selection": "highest precision among qualifying thresholds",
            "test_used": False,
        },
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "matrix_metadata_sha256": file_sha256(matrix.metadata_path),
        "seed": SEED,
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
        evaluation_result: dict[str, object] = {
            "train_rows": int(train_targets.size),
            "validation_rows": int(validation_targets.size),
            "training_attack_label_codes": sorted(training_attack_labels),
            "models": {},
        }
        models = evaluation_result["models"]
        assert isinstance(models, dict)

        dummy = DummyClassifier(strategy="prior", random_state=SEED)
        dummy.fit(np.zeros((train_targets.size, 1), dtype=np.uint8), train_targets)
        dummy_scores = probability_scores(
            dummy, np.zeros((validation_targets.size, 1), dtype=np.uint8)
        )
        dummy_threshold = select_threshold(validation_targets, dummy_scores)
        dummy_artifact = models_directory / f"{evaluation}-dummy.joblib"
        joblib.dump(dummy, dummy_artifact)
        threshold = float(dummy_threshold["threshold"])
        models["dummy"] = {
            "configuration": {"strategy": "prior", "random_state": SEED},
            "artifact": dummy_artifact.as_posix(),
            "artifact_sha256": file_sha256(dummy_artifact),
            "threshold_selection": dummy_threshold,
            "validation": classification_metrics(
                validation_targets, dummy_scores, threshold
            ),
            "validation_subgroups": subgroup_metrics(
                matrix,
                validation_mask,
                validation_targets,
                dummy_scores,
                threshold,
                training_attack_labels,
                evaluation,
            ),
        }
        del dummy, dummy_scores

        train_features = matrix.frame(train_mask)
        logistic = build_logistic_baseline(seed=SEED)
        logistic.fit(train_features, train_targets)
        del train_features
        validation_features = matrix.frame(validation_mask)
        logistic_scores = probability_scores(logistic, validation_features)
        del validation_features
        logistic_threshold = select_threshold(validation_targets, logistic_scores)
        logistic_artifact = (
            models_directory / f"{evaluation}-logistic-regression-sgd.joblib"
        )
        joblib.dump(logistic, logistic_artifact)
        threshold = float(logistic_threshold["threshold"])
        models["logistic_regression_sgd"] = {
            "configuration": {
                "family": "logistic regression",
                "optimizer": "stochastic gradient descent",
                "loss": "log_loss",
                "penalty": "l2",
                "alpha": 0.0001,
                "class_weight": "balanced",
                "max_iter": 50,
                "tol": 0.001,
                "average": True,
                "random_state": SEED,
            },
            "artifact": logistic_artifact.as_posix(),
            "artifact_sha256": file_sha256(logistic_artifact),
            "threshold_selection": logistic_threshold,
            "validation": classification_metrics(
                validation_targets, logistic_scores, threshold
            ),
            "validation_subgroups": subgroup_metrics(
                matrix,
                validation_mask,
                validation_targets,
                logistic_scores,
                threshold,
                training_attack_labels,
                evaluation,
            ),
        }
        del logistic, logistic_scores, train_mask, validation_mask
        evaluations[evaluation] = evaluation_result

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def evaluate_frozen_test(
    matrix_directory: Path,
    validation_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"test result already exists: {output_path}")
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if validation["contract"]["test_used"]:
        raise ValueError("validation record already marks test as used")
    matrix = ModelMatrix(matrix_directory)
    if file_sha256(matrix.metadata_path) != validation["matrix_metadata_sha256"]:
        raise ValueError("model matrix metadata differs from frozen validation record")

    report = {
        "stage": "final_test_evaluated_once",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation_record": validation_path.as_posix(),
        "validation_record_sha256_before_test": file_sha256(validation_path),
        "contract": validation["contract"] | {"test_used": True},
        "environment": validation["environment"],
        "matrix_metadata_sha256": validation["matrix_metadata_sha256"],
        "seed": validation["seed"],
        "evaluations": {},
    }
    for evaluation in EVALUATIONS:
        frozen_evaluation = validation["evaluations"][evaluation]
        training_attack_labels = set(
            frozen_evaluation["training_attack_label_codes"]
        )
        test_mask = matrix.mask(evaluation, "test")
        test_targets = np.asarray(matrix.target[test_mask], dtype=np.uint8)
        evaluation_result = {
            "train_rows": frozen_evaluation["train_rows"],
            "validation_rows": frozen_evaluation["validation_rows"],
            "test_rows": int(test_targets.size),
            "training_attack_label_codes": sorted(training_attack_labels),
            "models": {},
        }
        test_features: pd.DataFrame | None = None
        for model_name in MODEL_NAMES:
            frozen_model = frozen_evaluation["models"][model_name]
            artifact = Path(frozen_model["artifact"])
            if file_sha256(artifact) != frozen_model["artifact_sha256"]:
                raise ValueError(f"frozen model artifact changed: {artifact}")
            model = joblib.load(artifact)
            if model_name == "dummy":
                features: object = np.zeros(
                    (test_targets.size, 1), dtype=np.uint8
                )
            else:
                if test_features is None:
                    test_features = matrix.frame(test_mask)
                features = test_features
            scores = probability_scores(model, features)
            threshold = float(frozen_model["threshold_selection"]["threshold"])
            evaluation_result["models"][model_name] = {
                "configuration": frozen_model["configuration"],
                "artifact": frozen_model["artifact"],
                "artifact_sha256": frozen_model["artifact_sha256"],
                "threshold_selection": frozen_model["threshold_selection"],
                "validation": frozen_model["validation"],
                "validation_subgroups": frozen_model["validation_subgroups"],
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
        del test_features, test_mask
        report["evaluations"][evaluation] = evaluation_result

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
    parser.add_argument("--models-dir", type=Path, default=Path("models/ai-07"))
    parser.add_argument(
        "--validation-output",
        type=Path,
        default=Path("reports/ai-07-validation.json"),
    )
    parser.add_argument(
        "--test-output",
        type=Path,
        default=Path("reports/ai-07-baseline-results.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.stage == "validation":
        report = train_and_freeze(
            args.matrix_dir, args.models_dir, args.validation_output
        )
    else:
        report = evaluate_frozen_test(
            args.matrix_dir, args.validation_output, args.test_output
        )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
