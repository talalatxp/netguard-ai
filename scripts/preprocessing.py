"""Leakage-safe preprocessing helpers for CIC-IDS2017."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


RATE_FEATURES = ("Flow Bytes/s", "Flow Packets/s")


def replace_non_finite_values(frame: pd.DataFrame) -> pd.DataFrame:
    """Replace infinities with NaN and preserve their presence as indicators."""
    missing_features = [feature for feature in RATE_FEATURES if feature not in frame]
    if missing_features:
        raise ValueError(
            "missing required rate features: " + ", ".join(missing_features)
        )

    transformed = frame.copy()
    for feature in RATE_FEATURES:
        values = pd.to_numeric(transformed[feature], errors="raise")
        numeric_values = values.to_numpy(dtype=np.float64, na_value=np.nan)
        non_finite_mask = ~np.isfinite(numeric_values)
        infinite_mask = np.isinf(numeric_values)

        transformed[f"{feature}__missing"] = non_finite_mask.astype(np.uint8)
        transformed[feature] = values.mask(infinite_mask, np.nan)

    return transformed


def build_logistic_preprocessor() -> Pipeline:
    """Build an unfitted preprocessing pipeline for logistic regression."""
    return Pipeline(
        steps=[
            (
                "non_finite",
                FunctionTransformer(replace_non_finite_values, validate=False),
            ),
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )


def build_logistic_baseline(seed: int = 42) -> Pipeline:
    """Build the fixed leakage-safe logistic-regression baseline."""
    preprocessor = build_logistic_preprocessor()
    return Pipeline(
        steps=[
            *preprocessor.steps,
            (
                "classifier",
                SGDClassifier(
                    loss="log_loss",
                    penalty="l2",
                    alpha=0.0001,
                    class_weight="balanced",
                    max_iter=50,
                    tol=0.001,
                    shuffle=True,
                    random_state=seed,
                    average=True,
                ),
            ),
        ]
    )


def build_tree_preprocessor() -> Pipeline:
    """Build an unfitted preprocessing pipeline for tree classifiers."""
    return Pipeline(
        steps=[
            (
                "non_finite",
                FunctionTransformer(replace_non_finite_values, validate=False),
            ),
            ("imputer", SimpleImputer(strategy="median")),
        ]
    )


def build_random_forest_baseline(seed: int = 42) -> Pipeline:
    """Build the fixed resource-aware Random Forest comparison model."""
    preprocessor = build_tree_preprocessor()
    return Pipeline(
        steps=[
            *preprocessor.steps,
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=80,
                    max_depth=18,
                    min_samples_leaf=20,
                    max_features="sqrt",
                    bootstrap=True,
                    max_samples=0.35,
                    class_weight="balanced_subsample",
                    n_jobs=2,
                    random_state=seed,
                ),
            ),
        ]
    )


def build_hist_gradient_boosting_baseline(seed: int = 42) -> Pipeline:
    """Build the fixed histogram gradient-boosting comparison model."""
    preprocessor = build_tree_preprocessor()
    return Pipeline(
        steps=[
            *preprocessor.steps,
            (
                "classifier",
                HistGradientBoostingClassifier(
                    loss="log_loss",
                    learning_rate=0.08,
                    max_iter=150,
                    max_leaf_nodes=31,
                    min_samples_leaf=50,
                    l2_regularization=1.0,
                    class_weight="balanced",
                    early_stopping=True,
                    validation_fraction=0.1,
                    n_iter_no_change=15,
                    tol=1e-7,
                    random_state=seed,
                ),
            ),
        ]
    )
