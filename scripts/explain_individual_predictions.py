"""Generate frozen AI-15 SHAP explanations for individual HGB decisions."""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import shap
import sklearn

from train_baselines import ModelMatrix, file_sha256, probability_scores


EVALUATION = "random"
MODEL_NAME = "hist_gradient_boosting"
EXAMPLES_PER_CATEGORY = 3
CATEGORIES = ("true_positive", "false_positive", "false_negative")
RATE_INDICATORS = ("Flow Bytes/s__missing", "Flow Packets/s__missing")


def sigmoid(value: float) -> float:
    return float(1.0 / (1.0 + np.exp(-value)))


def select_score_range_examples(
    indices: np.ndarray,
    scores: np.ndarray,
    count: int = EXAMPLES_PER_CATEGORY,
) -> np.ndarray:
    """Select deterministic minimum, median, and maximum-score group members."""
    candidates = np.asarray(indices, dtype=np.int64)
    if candidates.size < count:
        raise ValueError(
            f"category contains {candidates.size} rows; at least {count} are required"
        )
    ordered = candidates[
        np.argsort(scores[candidates], kind="stable")
    ]
    positions = np.rint(np.linspace(0, ordered.size - 1, count)).astype(int)
    selected = ordered[positions]
    if np.unique(selected).size != count:
        raise ValueError("score-range selection produced duplicate rows")
    return selected


def category_indices(
    targets: np.ndarray, predictions: np.ndarray
) -> dict[str, np.ndarray]:
    return {
        "true_positive": np.flatnonzero((targets == 1) & (predictions == 1)),
        "false_positive": np.flatnonzero((targets == 0) & (predictions == 1)),
        "false_negative": np.flatnonzero((targets == 1) & (predictions == 0)),
    }


def contribution_records(
    feature_names: tuple[str, ...],
    feature_values: np.ndarray,
    shap_values: np.ndarray,
    direction: str,
    limit: int = 5,
) -> list[dict[str, object]]:
    if direction == "toward_attack":
        order = np.argsort(-shap_values, kind="stable")
        keep = [index for index in order if shap_values[index] > 0][:limit]
    elif direction == "toward_benign":
        order = np.argsort(shap_values, kind="stable")
        keep = [index for index in order if shap_values[index] < 0][:limit]
    else:
        raise ValueError(f"unsupported SHAP direction: {direction}")
    return [
        {
            "feature": feature_names[index],
            "model_input_value": float(feature_values[index]),
            "shap_log_odds": float(shap_values[index]),
        }
        for index in keep
    ]


def explain_hgb_rows(
    model: object,
    raw_features: object,
) -> dict[str, object]:
    """Explain rows and verify SHAP additivity against pipeline probabilities."""
    transformed = np.asarray(model[:-1].transform(raw_features), dtype=np.float64)
    classifier = model.named_steps["classifier"]
    explainer = shap.TreeExplainer(
        classifier,
        model_output="raw",
        feature_perturbation="tree_path_dependent",
    )
    explanation = explainer(transformed, check_additivity=True)
    values = np.asarray(explanation.values, dtype=np.float64)
    base_values = np.broadcast_to(
        np.asarray(explanation.base_values, dtype=np.float64).reshape(-1),
        (transformed.shape[0],),
    )
    raw_outputs = base_values + values.sum(axis=1)
    reconstructed = np.asarray([sigmoid(value) for value in raw_outputs])
    model_scores = probability_scores(model, raw_features)
    errors = np.abs(reconstructed - model_scores)
    if not np.all(errors <= 1e-10):
        raise ValueError(
            f"SHAP reconstruction exceeds tolerance: {float(errors.max())}"
        )
    return {
        "transformed": transformed,
        "values": values,
        "base_values": base_values,
        "raw_outputs": raw_outputs,
        "reconstructed_scores": reconstructed,
        "model_scores": model_scores,
        "absolute_errors": errors,
    }


def build_explanations(
    matrix_directory: Path,
    ai08_results_path: Path,
    ai09_results_path: Path,
    output_path: Path,
) -> dict[str, object]:
    if output_path.exists():
        raise FileExistsError(f"AI-15 explanation report already exists: {output_path}")
    ai08 = json.loads(ai08_results_path.read_text(encoding="utf-8"))
    ai09 = json.loads(ai09_results_path.read_text(encoding="utf-8"))
    frozen = ai08["evaluations"][EVALUATION]["models"][MODEL_NAME]
    artifact = Path(frozen["artifact"])
    if file_sha256(artifact) != frozen["artifact_sha256"]:
        raise ValueError(f"frozen HGB artifact changed: {artifact}")
    matrix = ModelMatrix(matrix_directory)
    expected_arrays = ai09["matrix_arrays_sha256"]
    for array_name, expected_hash in expected_arrays.items():
        record = matrix.metadata["arrays"][array_name]
        if file_sha256(matrix_directory / record["filename"]) != expected_hash:
            raise ValueError(f"matrix array changed: {array_name}")

    test_mask = matrix.mask(EVALUATION, "test")
    absolute_rows = np.flatnonzero(test_mask)
    features = matrix.frame(test_mask)
    targets = np.asarray(matrix.target[test_mask], dtype=np.uint8)
    labels = np.asarray(matrix.label_code[test_mask], dtype=np.uint8)
    source_codes = np.asarray(
        np.load(matrix_directory / "source_file_code.npy", mmap_mode="r")[test_mask],
        dtype=np.uint8,
    )
    model = joblib.load(artifact)
    scores = probability_scores(model, features)
    threshold = float(frozen["threshold_selection"]["threshold"])
    predictions = np.asarray(scores >= threshold, dtype=np.uint8)
    groups = category_indices(targets, predictions)
    selected_by_category = {
        category: select_score_range_examples(groups[category], scores)
        for category in CATEGORIES
    }
    selected = np.concatenate(
        [selected_by_category[category] for category in CATEGORIES]
    )
    selected_features = features.iloc[selected].copy()
    shap_result = explain_hgb_rows(model, selected_features)
    feature_names = tuple(matrix.metadata["feature_names"]) + RATE_INDICATORS
    if len(feature_names) != shap_result["values"].shape[1]:
        raise ValueError("transformed feature names do not match SHAP columns")
    label_names = {
        int(code): name for name, code in matrix.metadata["label_codes"].items()
    }
    source_names = {
        code: Path(path).name
        for code, path in enumerate(matrix.metadata["source_files"])
    }

    examples: list[dict[str, object]] = []
    offset = 0
    for category in CATEGORIES:
        for rank, local_index in enumerate(selected_by_category[category], start=1):
            shap_row = shap_result["values"][offset]
            model_inputs = shap_result["transformed"][offset]
            examples.append(
                {
                    "category": category,
                    "score_range_rank": rank,
                    "matrix_row_index_zero_based": int(absolute_rows[local_index]),
                    "source_file": source_names[int(source_codes[local_index])],
                    "label": label_names[int(labels[local_index])],
                    "target": "ATTACK" if targets[local_index] else "BENIGN",
                    "prediction": "ATTACK" if predictions[local_index] else "BENIGN",
                    "attack_score": float(scores[local_index]),
                    "frozen_threshold": threshold,
                    "score_margin": float(scores[local_index] - threshold),
                    "base_log_odds": float(shap_result["base_values"][offset]),
                    "output_log_odds": float(shap_result["raw_outputs"][offset]),
                    "reconstructed_attack_score": float(
                        shap_result["reconstructed_scores"][offset]
                    ),
                    "reconstruction_absolute_error": float(
                        shap_result["absolute_errors"][offset]
                    ),
                    "top_toward_attack": contribution_records(
                        feature_names, model_inputs, shap_row, "toward_attack"
                    ),
                    "top_toward_benign": contribution_records(
                        feature_names, model_inputs, shap_row, "toward_benign"
                    ),
                }
            )
            offset += 1

    report: dict[str, object] = {
        "stage": "ai_15_frozen_individual_shap_explanations",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "contract": {
            "descriptive_post_test_analysis_only": True,
            "model_retrained": False,
            "threshold_changed": False,
            "feature_selection_performed": False,
            "examples_selected_without_label_or_feature_inspection": True,
        },
        "selection": {
            "evaluation": EVALUATION,
            "partition": "test",
            "model": MODEL_NAME,
            "policy": "minimum, median, and maximum score within each error category",
            "categories": {
                category: {
                    "available_rows": int(groups[category].size),
                    "selected_rows": EXAMPLES_PER_CATEGORY,
                }
                for category in CATEGORIES
            },
        },
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "shap": shap.__version__,
            "joblib": joblib.__version__,
        },
        "model": {
            "artifact": artifact.as_posix(),
            "artifact_sha256": frozen["artifact_sha256"],
            "frozen_threshold": threshold,
            "test_metrics": frozen["test"],
        },
        "explanation": {
            "algorithm": "SHAP TreeExplainer",
            "model_output": "raw log-odds",
            "feature_perturbation": "tree_path_dependent",
            "additivity": "sigmoid(base_value + sum(SHAP)) = attack_score",
            "maximum_reconstruction_absolute_error": float(
                np.max(shap_result["absolute_errors"])
            ),
            "transformed_feature_count": len(feature_names),
            "transformed_feature_names": feature_names,
        },
        "examples": examples,
    }
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
        "--ai-08-results",
        type=Path,
        default=Path("reports/ai-08-model-comparison-results.json"),
    )
    parser.add_argument(
        "--ai-09-results",
        type=Path,
        default=Path("reports/ai-09-error-analysis.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/ai-15-individual-shap.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    build_explanations(
        args.matrix_dir,
        args.ai_08_results,
        args.ai_09_results,
        args.output,
    )
    print(f"AI-15 SHAP explanations written to {args.output}")


if __name__ == "__main__":
    main()
