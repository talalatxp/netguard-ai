"""Build the frozen AI-09 error and feature-importance analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from train_baselines import (
    EVALUATIONS,
    ModelMatrix,
    classification_metrics,
    file_sha256,
    probability_scores,
)


PARTITIONS = ("validation", "test")
MODEL_SOURCES = {
    "logistic_regression_sgd": "ai_07",
    "random_forest": "ai_08",
    "hist_gradient_boosting": "ai_08",
}
QUANTILES = (0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99)
PERMUTATION_REPEATS = 3
PERMUTATION_MAX_ROWS_PER_CLASS = 20_000
SEED = 42
EXPECTED_ARRAY_SHA256 = {
    "features": "e79c95118af3e47ae0f4f011460024a1e39cc07490625740a70552bf7798a1c7",
    "target": "0abe09d4526bb10f9f5b6572d9ed02a446960a0c24b7a5ed615664e64292a437",
    "random_partition": "c116743389bf0f9120650dfba06c7e25fb50994a966d60578272ab70f9ba3808",
    "temporal_partition": "230a5d94e20168ae596c0f150663b5dfdc5e31de40e7152434bf75f90c1c554b",
    "temporal_novel": "653b3c351e8a23ff2cdb5a89993e87e8b0006fc032fd4bb51380b25349f887a2",
    "label_code": "0a357949e6bd0afb13b15b149863094118fd113ed9f3508ac1fe09252e2d4e0b",
    "source_file_code": "51296e2f5ab6ac136594b7335d1d51e9e3ed143d0ecbdfab3e85fc8a947601ec",
}


def score_distribution(scores: np.ndarray) -> dict[str, object]:
    """Summarize a score vector without retaining row-level predictions."""
    values = np.asarray(scores, dtype=np.float64)
    if values.size == 0:
        return {"rows": 0, "mean": None, "minimum": None, "maximum": None, "quantiles": {}}
    quantile_values = np.quantile(values, QUANTILES)
    return {
        "rows": int(values.size),
        "mean": float(np.mean(values)),
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
        "quantiles": {
            f"q{int(quantile * 100):02d}": float(value)
            for quantile, value in zip(QUANTILES, quantile_values, strict=True)
        },
    }


def grouped_error_metrics(
    targets: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, object]:
    """Return threshold errors and class-conditional score distributions."""
    predictions = scores >= threshold
    benign = targets == 0
    attacks = targets == 1
    false_positive = benign & predictions
    false_negative = attacks & ~predictions
    return {
        "rows": int(targets.size),
        "attack_rows": int(np.count_nonzero(attacks)),
        "benign_rows": int(np.count_nonzero(benign)),
        "false_positive_count": int(np.count_nonzero(false_positive)),
        "false_negative_count": int(np.count_nonzero(false_negative)),
        "benign_scores": score_distribution(scores[benign]),
        "attack_scores": score_distribution(scores[attacks]),
        "false_positive_scores": score_distribution(scores[false_positive]),
        "false_negative_scores": score_distribution(scores[false_negative]),
    }


def breakdown_by_code(
    codes: np.ndarray,
    names: dict[int, str],
    targets: np.ndarray,
    scores: np.ndarray,
    threshold: float,
) -> list[dict[str, object]]:
    """Describe errors independently for every present label or source code."""
    results: list[dict[str, object]] = []
    predictions = scores >= threshold
    for code in np.unique(codes):
        code_value = int(code)
        mask = codes == code
        group_targets = targets[mask]
        group_predictions = predictions[mask]
        attacks = group_targets == 1
        benign = group_targets == 0
        attack_rows = int(np.count_nonzero(attacks))
        benign_rows = int(np.count_nonzero(benign))
        true_positive = int(np.count_nonzero(attacks & group_predictions))
        false_negative = attack_rows - true_positive
        false_positive = int(np.count_nonzero(benign & group_predictions))
        predicted_attack = true_positive + false_positive
        results.append(
            {
                "code": code_value,
                "name": names[code_value],
                "rows": int(np.count_nonzero(mask)),
                "attack_rows": attack_rows,
                "benign_rows": benign_rows,
                "true_positive": true_positive,
                "false_negative": false_negative,
                "false_positive": false_positive,
                "attack_recall": (
                    float(true_positive / attack_rows) if attack_rows else None
                ),
                "attack_precision": (
                    float(true_positive / predicted_attack)
                    if predicted_attack
                    else None
                ),
                "scores": score_distribution(scores[mask]),
            }
        )
    return results


def balanced_sample_indices(
    targets: np.ndarray,
    max_rows_per_class: int,
    seed: int,
) -> np.ndarray:
    """Select the same deterministic number of benign and attack rows."""
    benign = np.flatnonzero(targets == 0)
    attacks = np.flatnonzero(targets == 1)
    rows_per_class = min(max_rows_per_class, benign.size, attacks.size)
    if rows_per_class == 0:
        raise ValueError("permutation analysis requires both target classes")
    generator = np.random.default_rng(seed)
    selected = np.concatenate(
        [
            generator.choice(benign, rows_per_class, replace=False),
            generator.choice(attacks, rows_per_class, replace=False),
        ]
    )
    return np.sort(selected)


def stable_seed(*parts: object) -> int:
    payload = ":".join(str(part) for part in parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def permutation_feature_importance(
    model: object,
    features: pd.DataFrame,
    targets: np.ndarray,
    evaluation: str,
    model_name: str,
    repeats: int = PERMUTATION_REPEATS,
) -> dict[str, object]:
    """Measure validation PR-AUC loss after deterministic feature permutation."""
    baseline_scores = probability_scores(model, features)
    baseline_pr_auc = float(average_precision_score(targets, baseline_scores))
    working = features.copy()
    importances: list[dict[str, object]] = []
    for feature_index, feature_name in enumerate(features.columns):
        original = working.iloc[:, feature_index].to_numpy(copy=True)
        drops: list[float] = []
        for repeat in range(repeats):
            generator = np.random.default_rng(
                stable_seed(SEED, evaluation, model_name, feature_name, repeat)
            )
            working.iloc[:, feature_index] = generator.permutation(original)
            permuted_scores = probability_scores(model, working)
            permuted_pr_auc = float(
                average_precision_score(targets, permuted_scores)
            )
            drops.append(baseline_pr_auc - permuted_pr_auc)
        working.iloc[:, feature_index] = original
        importances.append(
            {
                "feature": str(feature_name),
                "mean_pr_auc_drop": float(np.mean(drops)),
                "std_pr_auc_drop": float(np.std(drops)),
                "repeats": [float(value) for value in drops],
            }
        )
    importances.sort(key=lambda item: item["mean_pr_auc_drop"], reverse=True)
    return {
        "method": "validation permutation importance using PR-AUC loss",
        "baseline_pr_auc_on_balanced_sample": baseline_pr_auc,
        "rows": int(targets.size),
        "rows_per_class": int(np.count_nonzero(targets == 0)),
        "repeats": repeats,
        "features": importances,
    }


def report_model_entry(
    evaluation: str,
    model_name: str,
    ai07: dict[str, object],
    ai08: dict[str, object],
) -> dict[str, object]:
    source = ai07 if MODEL_SOURCES[model_name] == "ai_07" else ai08
    return source["evaluations"][evaluation]["models"][model_name]


def verify_inputs(
    matrix: ModelMatrix,
    ai07_path: Path,
    ai07: dict[str, object],
    ai08_path: Path,
    ai08: dict[str, object],
) -> None:
    for array_name, expected_hash in EXPECTED_ARRAY_SHA256.items():
        array_record = matrix.metadata["arrays"][array_name]
        array_path = matrix.directory / array_record["filename"]
        if array_record["sha256"] != expected_hash:
            raise ValueError(f"unexpected declared hash for matrix array: {array_name}")
        if file_sha256(array_path) != expected_hash:
            raise ValueError(f"matrix array differs from the frozen data: {array_name}")
    if file_sha256(ai07_path) != ai08["ai_07_results"]["sha256"]:
        raise ValueError("AI-07 results differ from the AI-08 lineage record")
    if ai07["contract"]["test_used"] is not True:
        raise ValueError("AI-07 final test record is incomplete")
    if ai08["contract"]["test_used"] is not True:
        raise ValueError("AI-08 final test record is incomplete")
    for evaluation in EVALUATIONS:
        for model_name in MODEL_SOURCES:
            frozen = report_model_entry(evaluation, model_name, ai07, ai08)
            artifact = Path(frozen["artifact"])
            if file_sha256(artifact) != frozen["artifact_sha256"]:
                raise ValueError(f"frozen model changed: {artifact}")


def build_analysis(
    matrix_directory: Path,
    ai07_path: Path,
    ai08_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"AI-09 analysis already exists: {output_path}")
    matrix = ModelMatrix(matrix_directory)
    ai07 = json.loads(ai07_path.read_text(encoding="utf-8"))
    ai08 = json.loads(ai08_path.read_text(encoding="utf-8"))
    verify_inputs(matrix, ai07_path, ai07, ai08_path, ai08)

    source_codes = np.load(matrix_directory / "source_file_code.npy", mmap_mode="r")
    if source_codes.shape != matrix.target.shape:
        raise ValueError("source-file code array shape differs from target array")
    label_names = {
        int(code): name for name, code in matrix.metadata["label_codes"].items()
    }
    source_names = {
        code: Path(name).name
        for code, name in enumerate(matrix.metadata["source_files"])
    }
    report: dict[str, object] = {
        "stage": "ai_09_frozen_post_test_analysis",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "contract": {
            "descriptive_post_test_analysis_only": True,
            "models_retrained": False,
            "thresholds_changed": False,
            "features_selected": False,
            "future_changes_require_a_new_experiment": True,
        },
        "seed": SEED,
        "matrix_metadata_sha256": file_sha256(matrix.metadata_path),
        "matrix_arrays_sha256": EXPECTED_ARRAY_SHA256,
        "input_reports": {
            "ai_07": {"path": ai07_path.as_posix(), "sha256": file_sha256(ai07_path)},
            "ai_08": {"path": ai08_path.as_posix(), "sha256": file_sha256(ai08_path)},
        },
        "evaluations": {},
    }

    for evaluation in EVALUATIONS:
        evaluation_result: dict[str, object] = {"models": {}}
        validation_mask = matrix.mask(evaluation, "validation")
        validation_targets = np.asarray(matrix.target[validation_mask], dtype=np.uint8)
        sample_positions = balanced_sample_indices(
            validation_targets,
            PERMUTATION_MAX_ROWS_PER_CLASS,
            stable_seed(SEED, evaluation, "permutation_sample"),
        )
        validation_features = matrix.frame(validation_mask)
        sample_features = validation_features.iloc[sample_positions].copy()
        sample_targets = validation_targets[sample_positions]

        for model_name in MODEL_SOURCES:
            frozen = report_model_entry(evaluation, model_name, ai07, ai08)
            model = joblib.load(frozen["artifact"])
            threshold = float(frozen["threshold_selection"]["threshold"])
            model_result: dict[str, object] = {
                "artifact": frozen["artifact"],
                "artifact_sha256": frozen["artifact_sha256"],
                "frozen_threshold": threshold,
                "partitions": {},
            }
            for partition in PARTITIONS:
                mask = matrix.mask(evaluation, partition)
                targets = np.asarray(matrix.target[mask], dtype=np.uint8)
                features = matrix.frame(mask)
                scores = probability_scores(model, features)
                metrics = classification_metrics(targets, scores, threshold)
                expected = frozen[partition]
                for metric_name in ("attack_precision", "attack_recall", "attack_f1", "pr_auc"):
                    if not np.isclose(metrics[metric_name], expected[metric_name], atol=1e-12):
                        raise ValueError(
                            f"{evaluation} {model_name} {partition} {metric_name} "
                            "differs from the frozen report"
                        )
                labels = np.asarray(matrix.label_code[mask], dtype=np.uint8)
                sources = np.asarray(source_codes[mask], dtype=np.uint8)
                model_result["partitions"][partition] = {
                    "metrics": metrics,
                    "errors_and_scores": grouped_error_metrics(
                        targets, scores, threshold
                    ),
                    "by_attack_label": [
                        item
                        for item in breakdown_by_code(
                            labels, label_names, targets, scores, threshold
                        )
                        if item["attack_rows"] > 0
                    ],
                    "by_source_file": breakdown_by_code(
                        sources, source_names, targets, scores, threshold
                    ),
                }
            model_result["validation_permutation_importance"] = (
                permutation_feature_importance(
                    model,
                    sample_features,
                    sample_targets,
                    evaluation,
                    model_name,
                )
            )
            evaluation_result["models"][model_name] = model_result
        report["evaluations"][evaluation] = evaluation_result

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix-dir", type=Path, default=Path("data/processed/model-matrix")
    )
    parser.add_argument(
        "--ai-07-results",
        type=Path,
        default=Path("reports/ai-07-baseline-results.json"),
    )
    parser.add_argument(
        "--ai-08-results",
        type=Path,
        default=Path("reports/ai-08-model-comparison-results.json"),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("reports/ai-09-error-analysis.json")
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    build_analysis(
        args.matrix_dir,
        args.ai_07_results,
        args.ai_08_results,
        args.output,
    )
    print(f"AI-09 analysis written to {args.output}")


if __name__ == "__main__":
    main()
