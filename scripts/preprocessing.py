"""Leakage-safe preprocessing helpers for CIC-IDS2017."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
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
