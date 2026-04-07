"""
Abstract base class for all fraud detection models.

Every concrete model must implement:
  - fit(X, y) → self
  - predict_proba(X) → np.ndarray shape (n, 2)  columns: [P(licit), P(fraud)]
  - save(path)  / load(path)  — joblib for sklearn-compatible, torch.save for neural nets
  - model_name  (property)
  - feature_names (property)
"""
from __future__ import annotations

import abc
import logging
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


class FraudModel(abc.ABC):
    """Interface contract for all fraud detection models."""

    @property
    @abc.abstractmethod
    def model_name(self) -> str:
        """Unique lowercase identifier: 'random_forest', 'xgboost', 'lightgbm', etc."""

    @property
    @abc.abstractmethod
    def feature_names(self) -> list[str]:
        """Ordered list of feature names this model was trained on."""

    @abc.abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray, **kwargs) -> "FraudModel":
        """Train the model.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Binary labels (0=licit, 1=fraud)
        """

    @abc.abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probabilities.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Array of shape (n_samples, 2): [:, 0] = P(licit), [:, 1] = P(fraud)
        """

    @abc.abstractmethod
    def save(self, path: Path) -> None:
        """Persist model artefact to disk."""

    @abc.abstractmethod
    def load(self, path: Path) -> "FraudModel":
        """Load model artefact from disk and return self."""

    # ------------------------------------------------------------------
    # Concrete helpers (shared by all subclasses)
    # ------------------------------------------------------------------

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Return binary predictions.

        Args:
            X: Feature matrix
            threshold: Fraud probability cut-off (default 0.5)

        Returns:
            Binary array (n_samples,) — 1=fraud, 0=licit
        """
        proba = self.predict_proba(X)
        return (proba[:, 1] >= threshold).astype(np.int32)

    def fraud_probability(self, X: np.ndarray) -> np.ndarray:
        """Convenience wrapper returning only P(fraud)."""
        return self.predict_proba(X)[:, 1]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model_name={self.model_name!r})"


class SklearnFraudModel(FraudModel, abc.ABC):
    """Mixin for sklearn-compatible estimators (joblib save/load)."""

    _estimator = None   # set by subclass after fit

    def save(self, path: Path) -> None:
        import joblib
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._estimator, path)
        logger.info("saved %s → %s", self.model_name, path)

    def load(self, path: Path) -> "SklearnFraudModel":
        import joblib
        self._estimator = joblib.load(Path(path))
        logger.info("loaded %s ← %s", self.model_name, path)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self._estimator is None:
            raise RuntimeError(f"{self.model_name}: model not fitted or loaded")
        return self._estimator.predict_proba(X)
