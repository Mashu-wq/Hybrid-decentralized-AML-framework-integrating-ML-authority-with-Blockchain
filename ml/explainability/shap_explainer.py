"""
SHAP explainability for fraud detection models.

  - TreeExplainer  → RandomForest, XGBoost, LightGBM
  - DeepExplainer  → GNN / Autoencoder (PyTorch)
  - KernelExplainer → fallback for any model

Returns top-N (feature_name, shap_value) pairs for each prediction, plus the
base_value (expected model output on background dataset).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES

logger = logging.getLogger(__name__)


@dataclass
class SHAPResult:
    """SHAP output for a single prediction."""
    feature_names: list[str]
    shap_values: list[float]    # signed SHAP values for fraud class
    base_value: float           # model expected output (before seeing features)
    prediction: float           # actual model output for this instance


@dataclass
class SHAPContribution:
    """Top-N feature contribution for a single prediction."""
    feature_name: str
    shap_value: float
    feature_value: float


class TreeSHAPExplainer:
    """SHAP TreeExplainer for sklearn-compatible tree models (RF/XGBoost/LightGBM).

    Computes exact Shapley values — O(TLD) per sample where T=trees, L=leaves, D=depth.
    """

    def __init__(self, model, background_data: Optional[np.ndarray] = None) -> None:
        """
        Args:
            model: Fitted sklearn estimator (RF, XGBoost, or LightGBM).
            background_data: Optional background dataset for TreeExplainer.
                             If None, SHAP uses the tree leaf values as background.
        """
        self._model = model
        self._background = background_data
        self._explainer = None

    def _get_explainer(self):
        if self._explainer is None:
            try:
                import shap
            except ImportError as exc:
                raise ImportError("shap package is required") from exc
            self._explainer = shap.TreeExplainer(
                self._model,
                data=self._background,
                feature_perturbation="tree_path_dependent" if self._background is None else "interventional",
            )
        return self._explainer

    def explain(self, X: np.ndarray, top_n: int = 5) -> list[SHAPResult]:
        """Compute SHAP values for all rows in X.

        Args:
            X: Feature matrix (n_samples, n_features)
            top_n: Number of top features to return per sample (ignored here;
                   caller uses top_contributions() to slice).

        Returns:
            List of SHAPResult, one per sample.
        """
        explainer = self._get_explainer()
        shap_output = explainer(X)

        # shap_output.values shape depends on model type:
        # binary classifier → (n_samples, n_features, 2) or (n_samples, n_features)
        values = shap_output.values
        base   = shap_output.base_values

        if values.ndim == 3:
            # (n_samples, n_features, n_classes) → take fraud class (index 1)
            fraud_values = values[:, :, 1]
            base_fraud   = base[:, 1] if base.ndim > 1 else base
        else:
            fraud_values = values
            base_fraud   = base if base.ndim == 1 else base[:, 0]

        results = []
        for i in range(len(X)):
            results.append(SHAPResult(
                feature_names=SELECTED_FEATURE_NAMES,
                shap_values=fraud_values[i].tolist(),
                base_value=float(base_fraud[i]) if np.ndim(base_fraud) > 0 else float(base_fraud),
                prediction=float(self._model.predict_proba(X[i:i+1])[0, 1]),
            ))
        return results

    def top_contributions(
        self,
        X: np.ndarray,
        top_n: int = 5,
        feature_names: Optional[list[str]] = None,
    ) -> list[list[SHAPContribution]]:
        """Return top-N SHAP contributions per sample, sorted by |shap_value| desc.

        Args:
            X: Feature matrix (n_samples, n_features)
            top_n: Number of features to return per sample
            feature_names: Override default feature names

        Returns:
            Outer list per sample; inner list of top-N SHAPContribution
        """
        names = feature_names or SELECTED_FEATURE_NAMES
        results = self.explain(X)
        output = []
        for i, result in enumerate(results):
            sv  = np.array(result.shap_values)
            idx = np.argsort(np.abs(sv))[::-1][:top_n]
            contributions = [
                SHAPContribution(
                    feature_name=names[j] if j < len(names) else f"f{j}",
                    shap_value=float(sv[j]),
                    feature_value=float(X[i, j]),
                )
                for j in idx
            ]
            output.append(contributions)
        return output


class DeepSHAPExplainer:
    """SHAP DeepExplainer for PyTorch neural networks (GNN, Autoencoder).

    Uses a sample of background data as the reference distribution.
    """

    def __init__(self, model, background_data: np.ndarray) -> None:
        """
        Args:
            model: PyTorch nn.Module.
            background_data: Background samples (n_background, n_features).
                             100–200 samples is sufficient.
        """
        self._model = model
        self._background = background_data
        self._explainer = None

    def _get_explainer(self):
        if self._explainer is None:
            try:
                import shap
                import torch
            except ImportError as exc:
                raise ImportError("shap and torch are required for DeepSHAPExplainer") from exc

            device = next(self._model.parameters()).device
            bg_t   = torch.tensor(self._background, dtype=torch.float32).to(device)
            self._explainer = shap.DeepExplainer(self._model, bg_t)
        return self._explainer

    def top_contributions(
        self, X: np.ndarray, top_n: int = 5
    ) -> list[list[SHAPContribution]]:
        try:
            import shap
            import torch
        except ImportError as exc:
            raise ImportError("shap and torch required") from exc

        explainer = self._get_explainer()
        device    = next(self._model.parameters()).device
        X_t       = torch.tensor(X, dtype=torch.float32).to(device)
        shap_vals  = explainer.shap_values(X_t)  # list: [class0_vals, class1_vals]
        fraud_vals = np.array(shap_vals[1]) if isinstance(shap_vals, list) else np.array(shap_vals)

        output = []
        for i in range(len(X)):
            sv  = fraud_vals[i]
            idx = np.argsort(np.abs(sv))[::-1][:top_n]
            contributions = [
                SHAPContribution(
                    feature_name=SELECTED_FEATURE_NAMES[j] if j < len(SELECTED_FEATURE_NAMES) else f"f{j}",
                    shap_value=float(sv[j]),
                    feature_value=float(X[i, j]),
                )
                for j in idx
            ]
            output.append(contributions)
        return output
