"""Validated inference helpers for the local NetGuard AI demo."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from train_baselines import file_sha256, probability_scores


MODEL_NAMES = (
    "logistic_regression_sgd",
    "random_forest",
    "hist_gradient_boosting",
)
EVALUATIONS = ("random", "temporal")
MAX_BATCH_ROWS = 10_000


@dataclass(frozen=True)
class FrozenModelSpec:
    key: str
    display_name: str
    evaluation: str
    model_name: str
    artifact: Path
    artifact_sha256: str
    threshold: float
    validation_metrics: dict[str, object]
    test_metrics: dict[str, object]
    important_features: tuple[tuple[str, float], ...]
    caveat: str


class InputValidationError(ValueError):
    """Raised when an uploaded batch does not match the frozen feature contract."""


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_feature_names(split_summary_path: Path) -> tuple[str, ...]:
    summary = json.loads(split_summary_path.read_text(encoding="utf-8"))
    features = tuple(str(name) for name in summary["feature_names"])
    if len(features) != int(summary["feature_count"]):
        raise ValueError("split summary feature count does not match feature names")
    if len(features) != len(set(features)):
        raise ValueError("frozen feature names are not unique")
    return features


def _model_display_name(evaluation: str, model_name: str) -> str:
    evaluation_name = "Group-aware random" if evaluation == "random" else "Temporal stress test"
    model_names = {
        "logistic_regression_sgd": "Logistic Regression",
        "random_forest": "Random Forest",
        "hist_gradient_boosting": "Histogram Gradient Boosting",
    }
    return f"{evaluation_name} — {model_names[model_name]}"


def _model_caveat(evaluation: str, model_name: str) -> str:
    if evaluation == "random":
        return (
            "Random-split performance is an optimistic reference and does not "
            "demonstrate generalization to later attack families."
        )
    if model_name == "logistic_regression_sgd":
        return (
            "This temporal model retained Friday recall but produced 69,117 false "
            "positives in the frozen test."
        )
    if model_name == "random_forest":
        return (
            "This temporal model missed every Bot flow and 98% of PortScan flows "
            "in the frozen Friday test."
        )
    return (
        "This temporal model detected only 5.2% of Friday attacks at its frozen "
        "threshold; its score is not calibrated for new days."
    )


def load_model_specs(
    ai07_path: Path,
    ai08_path: Path,
    ai09_path: Path,
    root: Path | None = None,
) -> dict[str, FrozenModelSpec]:
    """Load the committed model, threshold, metric, and explanation contracts."""
    root = project_root() if root is None else root
    ai07 = json.loads(ai07_path.read_text(encoding="utf-8"))
    ai08 = json.loads(ai08_path.read_text(encoding="utf-8"))
    ai09 = json.loads(ai09_path.read_text(encoding="utf-8"))
    reports = {
        "logistic_regression_sgd": ai07,
        "random_forest": ai08,
        "hist_gradient_boosting": ai08,
    }
    specs: dict[str, FrozenModelSpec] = {}
    for evaluation in EVALUATIONS:
        for model_name in MODEL_NAMES:
            model_record = reports[model_name]["evaluations"][evaluation]["models"][model_name]
            analysis_record = ai09["evaluations"][evaluation]["models"][model_name]
            key = f"{evaluation}:{model_name}"
            specs[key] = FrozenModelSpec(
                key=key,
                display_name=_model_display_name(evaluation, model_name),
                evaluation=evaluation,
                model_name=model_name,
                artifact=root / model_record["artifact"],
                artifact_sha256=str(model_record["artifact_sha256"]),
                threshold=float(model_record["threshold_selection"]["threshold"]),
                validation_metrics=dict(model_record["validation"]),
                test_metrics=dict(model_record["test"]),
                important_features=tuple(
                    (
                        str(item["feature"]),
                        float(item["mean_pr_auc_drop"]),
                    )
                    for item in analysis_record["validation_permutation_importance"][
                        "features"
                    ][:10]
                ),
                caveat=_model_caveat(evaluation, model_name),
            )
    return specs


def prepare_input_frame(
    frame: pd.DataFrame,
    expected_features: tuple[str, ...],
    max_rows: int = MAX_BATCH_ROWS,
) -> pd.DataFrame:
    """Validate and order one uploaded batch without silently dropping bad rows."""
    if frame.empty:
        raise InputValidationError("The uploaded CSV contains no data rows.")
    if len(frame) > max_rows:
        raise InputValidationError(
            f"The demo accepts at most {max_rows:,} rows per batch; received {len(frame):,}."
        )
    normalized_columns = [str(column).strip() for column in frame.columns]
    if len(normalized_columns) != len(set(normalized_columns)):
        raise InputValidationError(
            "Column names are duplicated after surrounding whitespace is removed."
        )
    prepared = frame.copy()
    prepared.columns = normalized_columns
    if "Label" in prepared.columns:
        prepared = prepared.drop(columns=["Label"])

    expected = set(expected_features)
    actual = set(prepared.columns)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    problems: list[str] = []
    if missing:
        problems.append("missing columns: " + ", ".join(missing))
    if extra:
        problems.append("unexpected columns: " + ", ".join(extra))
    if problems:
        raise InputValidationError("; ".join(problems))

    ordered = prepared.loc[:, expected_features]
    converted = pd.DataFrame(index=ordered.index)
    for feature in expected_features:
        try:
            converted[feature] = pd.to_numeric(ordered[feature], errors="raise")
        except (TypeError, ValueError) as error:
            raise InputValidationError(
                f"Column {feature!r} contains a non-numeric value. The batch was not scored."
            ) from error
    return converted


def load_verified_model(spec: FrozenModelSpec) -> object:
    if not spec.artifact.is_file():
        raise FileNotFoundError(
            f"Frozen model artifact not found: {spec.artifact}. Reproduce AI-07/AI-08 first."
        )
    actual_hash = file_sha256(spec.artifact)
    if actual_hash != spec.artifact_sha256:
        raise ValueError(
            f"Frozen model hash mismatch for {spec.artifact}: "
            f"expected {spec.artifact_sha256}, received {actual_hash}"
        )
    return joblib.load(spec.artifact)


def predict_rows(
    model: object,
    features: pd.DataFrame,
    threshold: float,
) -> pd.DataFrame:
    scores = probability_scores(model, features)
    if not np.all(np.isfinite(scores)):
        raise ValueError("model returned a non-finite attack score")
    predictions = np.where(scores >= threshold, "ATTACK", "BENIGN")
    return pd.DataFrame(
        {
            "row_number": np.arange(1, len(features) + 1),
            "attack_score": scores,
            "frozen_threshold": np.full(len(features), threshold),
            "prediction": predictions,
        }
    )
