"""
LightGBM fraud detection model — best performer by ROC-AUC.

Training results (Google Colab):
  Precision  : 64.61 %
  Recall     : 68.18 %
  F1         : 66.35 %
  ROC-AUC    : 96.49 %   ← highest of three models
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES
from ml.models.base import SklearnFraudModel

logger = logging.getLogger(__name__)

_DEFAULT_PARAMS: dict = {
    "n_estimators": 500,
    "max_depth": -1,          # no limit; controlled by num_leaves
    "num_leaves": 63,
    "learning_rate": 0.05,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,
    "min_child_samples": 20,
    "is_unbalance": True,     # handles class imbalance natively
    "metric": "auc",
    "random_state": 42,
    "n_jobs": -1,
    "verbose": -1,
}


class LightGBMModel(SklearnFraudModel):
    """LightGBM gradient boosted trees — best single model for fraud detection."""

    def __init__(self, params: Optional[dict] = None) -> None:
        self._params = {**_DEFAULT_PARAMS, **(params or {})}
        self._estimator = None
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "lightgbm"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        early_stopping_rounds: int = 50,
        **kwargs,
    ) -> "LightGBMModel":
        """Train LightGBM.

        Args:
            X, y: Training data (post-SMOTE).
            X_val, y_val: Optional hold-out for early stopping.
            early_stopping_rounds: Patience (only used when val set provided).
        """
        try:
            import lightgbm as lgb
        except ImportError as exc:
            raise ImportError("lightgbm package is required") from exc

        logger.info(
            "training LightGBM: samples=%d, fraud=%d (%.1f%%)",
            len(y), int(y.sum()), 100 * y.mean(),
        )

        self._estimator = lgb.LGBMClassifier(**self._params)

        fit_kwargs: dict = {"feature_name": self._feature_names}
        if X_val is not None and y_val is not None:
            callbacks = [
                lgb.early_stopping(early_stopping_rounds, verbose=False),
                lgb.log_evaluation(period=100),
            ]
            fit_kwargs["eval_set"] = [(X_val, y_val)]
            fit_kwargs["callbacks"] = callbacks

        self._estimator.fit(X, y, **fit_kwargs)
        logger.info(
            "LightGBM training complete, best_iteration=%s",
            getattr(self._estimator, "best_iteration_", "N/A"),
        )
        return self

    def feature_importances(self, importance_type: str = "gain") -> np.ndarray:
        """Return feature importances by split count or gain."""
        if self._estimator is None:
            raise RuntimeError("model not fitted")
        return self._estimator.booster_.feature_importance(importance_type=importance_type)

    def top_features(self, n: int = 10) -> list[tuple[str, float]]:
        importances = self.feature_importances()
        indices = np.argsort(importances)[::-1][:n]
        return [(self._feature_names[i], float(importances[i])) for i in indices]
