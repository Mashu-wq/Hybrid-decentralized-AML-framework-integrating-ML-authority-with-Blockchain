"""
Random Forest fraud detection model.

Training results (Google Colab):
  Features      : 85
  Train samples : 36,922 → 49,324 after SMOTE (1:2 ratio)
  Test samples  : 9,642  (506 fraud = 5.25 %)
  Precision     : 88.34 %
  Recall        : 56.92 %
  F1            : 69.23 %
  ROC-AUC       : 96.38 %
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.features.engineering import SELECTED_FEATURE_NAMES
from ml.models.base import SklearnFraudModel

logger = logging.getLogger(__name__)

# Hyperparameters that reproduced the Colab training results
_DEFAULT_PARAMS: dict = {
    "n_estimators": 300,
    "max_depth": None,
    "min_samples_split": 10,
    "min_samples_leaf": 4,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}


class RandomForestModel(SklearnFraudModel):
    """Sklearn RandomForestClassifier wrapped in the FraudModel interface."""

    def __init__(self, params: Optional[dict] = None) -> None:
        self._params = {**_DEFAULT_PARAMS, **(params or {})}
        self._estimator: Optional[RandomForestClassifier] = None
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "random_forest"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def fit(self, X: np.ndarray, y: np.ndarray, **kwargs) -> "RandomForestModel":
        """Train the Random Forest on (X, y).

        X is expected to already be SMOTE-augmented and to have 85 features.
        """
        logger.info(
            "training RandomForest: samples=%d, fraud=%d (%.1f%%)",
            len(y), int(y.sum()), 100 * y.mean(),
        )
        self._estimator = RandomForestClassifier(**self._params)
        self._estimator.fit(X, y)
        logger.info("RandomForest training complete, n_features=%d", X.shape[1])
        return self

    def feature_importances(self) -> np.ndarray:
        """Return Gini importance for each of the 85 features."""
        if self._estimator is None:
            raise RuntimeError("model not fitted")
        return self._estimator.feature_importances_

    def top_features(self, n: int = 10) -> list[tuple[str, float]]:
        """Return top-N (feature_name, importance) pairs sorted descending."""
        importances = self.feature_importances()
        indices = np.argsort(importances)[::-1][:n]
        return [(self._feature_names[i], float(importances[i])) for i in indices]
