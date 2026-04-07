"""
Ensemble model — weighted average of RF + XGBoost + LightGBM predictions.

Weights are set proportional to ROC-AUC from the Colab training run:
  LightGBM  : 0.9649 → weight 0.35
  RF        : 0.9638 → weight 0.33
  XGBoost   : 0.9597 → weight 0.32

A/B testing:
  If `challenger_model` and `ab_ratio` are set, `ab_ratio` fraction of calls
  are routed to the challenger; the rest go to the champion ensemble.
"""
from __future__ import annotations

import logging
import random
from pathlib import Path
from typing import Optional

import numpy as np

from ml.models.base import FraudModel
from ml.features.engineering import SELECTED_FEATURE_NAMES

logger = logging.getLogger(__name__)

# ROC-AUC based weights (sum = 1.00)
DEFAULT_WEIGHTS: dict[str, float] = {
    "lightgbm":     0.35,
    "random_forest": 0.33,
    "xgboost":      0.32,
}


class EnsembleModel(FraudModel):
    """Weighted-average ensemble of tree-based fraud models."""

    def __init__(
        self,
        models: Optional[dict[str, FraudModel]] = None,
        weights: Optional[dict[str, float]] = None,
        challenger_model: Optional[FraudModel] = None,
        ab_ratio: float = 0.0,
    ) -> None:
        """
        Args:
            models: dict of model_name → FraudModel instances.
            weights: dict of model_name → weight (must sum to 1.0).
            challenger_model: Optional A/B challenger (any FraudModel).
            ab_ratio: Fraction of predict calls to route to challenger (0–1).
        """
        self._models: dict[str, FraudModel] = models or {}
        self._weights = weights or DEFAULT_WEIGHTS
        self._challenger = challenger_model
        self._ab_ratio = ab_ratio
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "ensemble"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def add_model(self, model: FraudModel, weight: Optional[float] = None) -> None:
        """Register a base model. Weight defaults to equal share if not provided."""
        self._models[model.model_name] = model
        if weight is not None:
            self._weights[model.model_name] = weight

    def fit(self, X: np.ndarray, y: np.ndarray, **kwargs) -> "EnsembleModel":
        """Train all registered base models (in-place)."""
        for name, model in self._models.items():
            logger.info("fitting ensemble member: %s", name)
            model.fit(X, y, **kwargs)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Weighted average of base model probabilities.

        If A/B testing is active and the coin flip routes to challenger,
        the challenger model is used instead.
        """
        if self._challenger is not None and random.random() < self._ab_ratio:
            logger.debug("a/b: routing to challenger %s", self._challenger.model_name)
            return self._challenger.predict_proba(X)

        if not self._models:
            raise RuntimeError("EnsembleModel has no base models loaded")

        weighted_proba = np.zeros((X.shape[0], 2), dtype=np.float64)
        total_weight = 0.0

        for name, model in self._models.items():
            w = self._weights.get(name, 1.0)
            proba = model.predict_proba(X).astype(np.float64)
            weighted_proba += w * proba
            total_weight += w

        if total_weight == 0:
            raise RuntimeError("All ensemble weights are zero")

        return (weighted_proba / total_weight).astype(np.float32)

    def per_model_probabilities(self, X: np.ndarray) -> dict[str, float]:
        """Return each base model's fraud probability for a single sample.

        Args:
            X: Feature array of shape (1, n_features)

        Returns:
            dict mapping model_name → P(fraud)
        """
        result: dict[str, float] = {}
        for name, model in self._models.items():
            proba = model.predict_proba(X)
            result[name] = float(proba[0, 1])
        return result

    def save(self, path: Path) -> None:
        """Save ensemble metadata (weights); base models must be saved separately."""
        import json
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "weights": self._weights,
            "ab_ratio": self._ab_ratio,
            "members": list(self._models.keys()),
        }
        path.with_suffix(".json").write_text(json.dumps(meta, indent=2))
        logger.info("ensemble metadata saved → %s", path)

    def load(self, path: Path) -> "EnsembleModel":
        """Load ensemble metadata (weights)."""
        import json
        meta = json.loads(Path(path).with_suffix(".json").read_text())
        self._weights = meta.get("weights", DEFAULT_WEIGHTS)
        self._ab_ratio = meta.get("ab_ratio", 0.0)
        return self
