"""
XGBoost fraud detection model with optional Optuna hyperparameter search.

Training results (Google Colab):
  Precision  : 70.64 %
  Recall     : 63.24 %
  F1         : 66.74 %
  ROC-AUC    : 95.97 %
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
    "max_depth": 6,
    "learning_rate": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 5,
    "scale_pos_weight": 9,     # approx. licit/fraud ratio in original data
    "eval_metric": "auc",
    "random_state": 42,
    "n_jobs": -1,
    "use_label_encoder": False,
}


class XGBoostModel(SklearnFraudModel):
    """XGBoost gradient boosted trees for fraud detection."""

    def __init__(self, params: Optional[dict] = None) -> None:
        self._params = {**_DEFAULT_PARAMS, **(params or {})}
        self._estimator = None
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "xgboost"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        tune: bool = False,
        n_trials: int = 30,
        **kwargs,
    ) -> "XGBoostModel":
        """Train XGBoost.

        Args:
            X, y: Training features and labels (post-SMOTE).
            X_val, y_val: Optional validation set for early stopping.
            tune: If True, run Optuna hyperparameter search first.
            n_trials: Number of Optuna trials (only used when tune=True).
        """
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise ImportError("xgboost package is required") from exc

        if tune:
            best_params = _optuna_search(X, y, n_trials=n_trials)
            self._params.update(best_params)
            logger.info("Optuna best params: %s", best_params)

        logger.info(
            "training XGBoost: samples=%d, fraud=%d (%.1f%%)",
            len(y), int(y.sum()), 100 * y.mean(),
        )

        params = dict(self._params)
        params.pop("use_label_encoder", None)  # removed in xgboost >= 1.6

        self._estimator = XGBClassifier(**params)

        fit_kwargs: dict = {}
        if X_val is not None and y_val is not None:
            fit_kwargs["eval_set"] = [(X_val, y_val)]
            fit_kwargs["verbose"] = 50

        self._estimator.fit(X, y, **fit_kwargs)
        logger.info("XGBoost training complete")
        return self


def _optuna_search(X: np.ndarray, y: np.ndarray, n_trials: int = 30) -> dict:
    """Run Optuna TPE search for XGBoost hyperparameters.

    Returns best parameter dict (to update base params with).
    """
    try:
        import optuna
        from xgboost import XGBClassifier
        from sklearn.model_selection import StratifiedKFold, cross_val_score
    except ImportError as exc:
        logger.warning("Optuna or xgboost not available: %s — skipping tuning", exc)
        return {}

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial: "optuna.Trial") -> float:
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 200, 800),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 20),
            "scale_pos_weight": trial.suggest_float("scale_pos_weight", 1.0, 15.0),
            "eval_metric": "auc",
            "random_state": 42,
            "n_jobs": -1,
        }
        clf = XGBClassifier(**params)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        scores = cross_val_score(clf, X, y, cv=cv, scoring="roc_auc", n_jobs=-1)
        return float(scores.mean())

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=n_trials, show_progress_bar=False)
    return study.best_params
