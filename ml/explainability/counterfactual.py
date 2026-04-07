"""
Perturbation-based counterfactual explanation generator.

Answers: "What minimal feature changes would bring this transaction's fraud
probability below `target_prob`?"

Algorithm:
  1. Start with the original feature vector.
  2. Identify the top-K features by |SHAP value| (most influential).
  3. For each influential feature, compute a gradient-based perturbation
     direction using numerical finite-differences.
  4. Iteratively nudge features in the descending-fraud-probability direction
     until fraud_prob <= target_prob or max_iterations is reached.
  5. Return the minimum set of changed features.

This is a model-agnostic approach requiring only predict_proba().
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES

logger = logging.getLogger(__name__)

_EPSILON = 1e-4   # finite-difference step size


@dataclass
class CounterfactualChange:
    feature_name:    str
    current_value:   float
    suggested_value: float
    delta:           float


@dataclass
class CounterfactualResult:
    prediction_id:  str
    changes:        list[CounterfactualChange]
    resulting_prob: float
    achievable:     bool
    iterations_used: int


class CounterfactualExplainer:
    """Perturbation-based counterfactual generator.

    Args:
        predict_fn: Callable (n, f) → (n, 2), probability output of the model.
        feature_names: Column names; must match the feature dimension of instances passed to explain().
        max_iter:   Maximum gradient descent iterations.
        step_size:  Learning rate for feature perturbations.
        top_k:      Number of most-influential features to perturb.
    """

    def __init__(
        self,
        predict_fn: Callable[[np.ndarray], np.ndarray],
        feature_names: Optional[list[str]] = None,
        max_iter:   int = 100,
        step_size:  float = 0.05,
        top_k:      int = 10,
    ) -> None:
        self._predict_fn   = predict_fn
        self._feature_names = feature_names or SELECTED_FEATURE_NAMES
        self._max_iter     = max_iter
        self._step_size    = step_size
        self._top_k        = top_k

    def explain(
        self,
        instance: np.ndarray,
        target_prob: float = 0.3,
        prediction_id: str = "",
        shap_importances: Optional[np.ndarray] = None,
    ) -> CounterfactualResult:
        """Generate counterfactual for a single instance.

        Args:
            instance: 1-D array of shape (n_features,).
            target_prob: Target fraud probability (e.g., 0.3 → "non-fraud").
            prediction_id: Opaque ID from PredictFraudResponse.
            shap_importances: Optional SHAP values to prioritise which features
                              to perturb.  If None, numerical gradient is used.

        Returns:
            CounterfactualResult — includes list of suggested feature changes.
        """
        x = instance.copy().astype(np.float64)
        x_orig = x.copy()

        # Select features to perturb: top-K by |SHAP| or by numerical gradient
        if shap_importances is not None and len(shap_importances) == len(x):
            top_k_idx = np.argsort(np.abs(shap_importances))[::-1][: self._top_k]
        else:
            # Compute numerical gradient ∂P(fraud)/∂x_i
            top_k_idx = self._numerical_top_k(x)

        current_prob = self._fraud_prob(x)
        iteration = 0

        if current_prob <= target_prob:
            # Already below target — no changes needed
            return CounterfactualResult(
                prediction_id=prediction_id,
                changes=[],
                resulting_prob=current_prob,
                achievable=True,
                iterations_used=0,
            )

        for iteration in range(1, self._max_iter + 1):
            # Compute gradient for selected features
            grad = self._numerical_gradient(x, top_k_idx)

            # Update: step in the direction that DECREASES fraud prob
            x[top_k_idx] -= self._step_size * grad

            current_prob = self._fraud_prob(x)
            if current_prob <= target_prob:
                break

        changes = []
        for i in top_k_idx:
            delta = float(x[i] - x_orig[i])
            if abs(delta) > _EPSILON:
                changes.append(CounterfactualChange(
                    feature_name=self._feature_names[i] if i < len(self._feature_names) else f"f{i}",
                    current_value=float(x_orig[i]),
                    suggested_value=float(x[i]),
                    delta=delta,
                ))

        # Sort changes by |delta| descending
        changes.sort(key=lambda c: abs(c.delta), reverse=True)

        achievable = current_prob <= target_prob
        if not achievable:
            logger.debug(
                "counterfactual not achievable in %d iterations: final_prob=%.3f target=%.3f",
                iteration, current_prob, target_prob,
            )

        return CounterfactualResult(
            prediction_id=prediction_id,
            changes=changes,
            resulting_prob=float(current_prob),
            achievable=achievable,
            iterations_used=iteration,
        )

    def _fraud_prob(self, x: np.ndarray) -> float:
        proba = self._predict_fn(x.reshape(1, -1).astype(np.float32))
        return float(proba[0, 1])

    def _numerical_gradient(self, x: np.ndarray, indices: np.ndarray) -> np.ndarray:
        """Finite-difference gradient ∂P(fraud)/∂x_i for selected feature indices."""
        grad = np.zeros(len(indices), dtype=np.float64)
        for k, i in enumerate(indices):
            x_plus  = x.copy(); x_plus[i]  += _EPSILON
            x_minus = x.copy(); x_minus[i] -= _EPSILON
            grad[k] = (self._fraud_prob(x_plus) - self._fraud_prob(x_minus)) / (2 * _EPSILON)
        return grad

    def _numerical_top_k(self, x: np.ndarray) -> np.ndarray:
        """Find top-K features by numerical gradient magnitude."""
        all_grad = np.zeros(len(x), dtype=np.float64)
        for i in range(len(x)):
            x_plus  = x.copy(); x_plus[i]  += _EPSILON
            x_minus = x.copy(); x_minus[i] -= _EPSILON
            all_grad[i] = abs(
                (self._fraud_prob(x_plus) - self._fraud_prob(x_minus)) / (2 * _EPSILON)
            )
        return np.argsort(all_grad)[::-1][: self._top_k]
