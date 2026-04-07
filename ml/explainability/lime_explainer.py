"""
LIME (Local Interpretable Model-agnostic Explanations) for fraud detection.

Uses LimeTabularExplainer with the training data as background distribution.
LIME fits a locally linear model around a single prediction instance to produce
human-readable feature weights.

Returns LIMEResult per instance including:
  - feature_weights: list of (name, weight, condition_string)
  - local_accuracy: R^2 of the local linear model
  - intercept: local model intercept (≈ base probability)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES

logger = logging.getLogger(__name__)


@dataclass
class LIMEFeatureWeight:
    feature_name: str
    weight: float        # positive → increases fraud prob, negative → decreases
    condition: str       # e.g. "velocity_1h > 5.2"


@dataclass
class LIMEResult:
    prediction_id: str
    feature_weights: list[LIMEFeatureWeight]
    local_accuracy: float
    intercept: float


class LIMEFraudExplainer:
    """LIME explainer for all fraud models (model-agnostic via predict_fn).

    Args:
        training_data: Representative sample of training features (n_samples, n_features).
                       Used to estimate the local neighbourhood distribution.
        feature_names: Column names matching training_data columns.
        num_features:  Number of LIME features to return per explanation.
        num_samples:   Neighbourhood sample size for LIME perturbation.
    """

    def __init__(
        self,
        training_data: np.ndarray,
        feature_names: Optional[list[str]] = None,
        num_features: int = 10,
        num_samples:  int = 1000,
    ) -> None:
        self._training_data  = training_data
        self._feature_names  = feature_names or SELECTED_FEATURE_NAMES
        self._num_features   = num_features
        self._num_samples    = num_samples
        self._explainer      = None

    def _get_explainer(self):
        if self._explainer is None:
            try:
                from lime.lime_tabular import LimeTabularExplainer
            except ImportError as exc:
                raise ImportError("lime package is required: pip install lime") from exc
            self._explainer = LimeTabularExplainer(
                training_data=self._training_data,
                feature_names=self._feature_names,
                class_names=["licit", "fraud"],
                mode="classification",
                discretize_continuous=True,
                random_state=42,
            )
        return self._explainer

    def explain_instance(
        self,
        instance: np.ndarray,
        predict_fn: Callable[[np.ndarray], np.ndarray],
        prediction_id: str = "",
        num_features: Optional[int] = None,
    ) -> LIMEResult:
        """Generate LIME explanation for a single transaction.

        Args:
            instance: 1-D feature array of shape (n_features,)
            predict_fn: Model predict_proba function: (n, f) → (n, 2)
            prediction_id: Opaque ID linking to the original PredictFraudResponse
            num_features: Override default num_features for this call

        Returns:
            LIMEResult with sorted feature weights (largest |weight| first)
        """
        explainer = self._get_explainer()
        n_feat    = num_features or self._num_features

        exp = explainer.explain_instance(
            data_row=instance,
            predict_fn=predict_fn,
            num_features=n_feat,
            num_samples=self._num_samples,
            labels=(1,),  # explain fraud class
        )

        # Extract weights and sort by |weight| descending
        weights_raw = exp.as_list(label=1)
        weights_raw.sort(key=lambda x: abs(x[1]), reverse=True)

        feature_weights = [
            LIMEFeatureWeight(
                feature_name=_extract_feature_name(cond, self._feature_names),
                weight=float(w),
                condition=cond,
            )
            for cond, w in weights_raw
        ]

        # Local model score (R^2 of local ridge regression fit)
        try:
            local_accuracy = float(exp.score)
        except AttributeError:
            local_accuracy = 0.0

        # Intercept of local model
        try:
            intercept = float(exp.intercept.get(1, 0.0))
        except (AttributeError, TypeError):
            intercept = 0.0

        return LIMEResult(
            prediction_id=prediction_id,
            feature_weights=feature_weights,
            local_accuracy=local_accuracy,
            intercept=intercept,
        )


def _extract_feature_name(condition: str, feature_names: list[str]) -> str:
    """Parse the feature name from a LIME condition string.

    LIME returns conditions like "feature_3 > 0.50" or "0.10 < feature_42 <= 0.80".
    We find which known feature name appears in the condition string.
    """
    for name in feature_names:
        if name in condition:
            return name
    # Fallback: return the full condition (unknown feature)
    return condition.split(" ")[0]
