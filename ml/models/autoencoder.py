"""
Autoencoder-based anomaly detector for unsupervised fraud detection.

Architecture:
  Encoder: 85 → 64 → 32 → 16
  Decoder: 16 → 32 → 64 → 85
  Loss:    MSE reconstruction error on licit transactions only
  Inference: flag as fraud if reconstruction error > threshold (mean + k*std)

This model complements the supervised tree models — it can detect novel
fraud patterns not seen during supervised training.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np

from ml.features.engineering import SELECTED_FEATURE_NAMES
from ml.models.base import FraudModel

logger = logging.getLogger(__name__)


class AutoencoderModel(FraudModel):
    """Reconstruction-error anomaly detector based on a deep autoencoder."""

    def __init__(
        self,
        input_dim: int = 85,
        hidden_dims: tuple[int, ...] = (64, 32, 16),
        dropout: float = 0.2,
        threshold_k: float = 3.0,  # mean + k*std of licit errors
    ) -> None:
        self._input_dim   = input_dim
        self._hidden_dims = hidden_dims
        self._dropout     = dropout
        self._threshold_k = threshold_k
        self._model       = None
        self._threshold: Optional[float] = None
        self._feature_names = SELECTED_FEATURE_NAMES.copy()

    @property
    def model_name(self) -> str:
        return "autoencoder"

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def _build_model(self):
        try:
            import torch.nn as nn
        except ImportError as exc:
            raise ImportError("torch is required for AutoencoderModel") from exc

        dims = [self._input_dim] + list(self._hidden_dims)

        class _AE(nn.Module):
            def __init__(self, dims, dropout):
                super().__init__()
                # Encoder
                enc_layers = []
                for i in range(len(dims) - 1):
                    enc_layers += [nn.Linear(dims[i], dims[i + 1]), nn.ReLU(), nn.Dropout(dropout)]
                self.encoder = nn.Sequential(*enc_layers)
                # Decoder (reversed)
                dec_layers = []
                for i in range(len(dims) - 1, 0, -1):
                    dec_layers += [nn.Linear(dims[i], dims[i - 1])]
                    if i > 1:
                        dec_layers += [nn.ReLU(), nn.Dropout(dropout)]
                self.decoder = nn.Sequential(*dec_layers)

            def forward(self, x):
                return self.decoder(self.encoder(x))

        try:
            import torch
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self._model = _AE(dims, self._dropout).to(device)
        except ImportError:
            self._model = None

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        epochs: int = 30,
        batch_size: int = 512,
        lr: float = 1e-3,
        **kwargs,
    ) -> "AutoencoderModel":
        """Train autoencoder on licit transactions only (unsupervised).

        After training, calibrate the reconstruction-error threshold on the
        full training set so predict_proba() returns calibrated probabilities.
        """
        try:
            import torch
            import torch.nn as nn
            from torch.utils.data import DataLoader, TensorDataset
        except ImportError as exc:
            raise ImportError("torch is required for AutoencoderModel.fit") from exc

        if self._model is None:
            self._build_model()

        device = next(self._model.parameters()).device  # type: ignore[union-attr]

        # Train only on licit samples (y == 0)
        X_licit = X[y == 0]
        logger.info("autoencoder training on %d licit samples", len(X_licit))

        X_t = torch.tensor(X_licit, dtype=torch.float32).to(device)
        dataset = TensorDataset(X_t)
        loader  = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=lr)  # type: ignore
        criterion = nn.MSELoss()

        self._model.train()  # type: ignore
        for epoch in range(epochs):
            total_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = self._model(batch)  # type: ignore
                loss  = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            if (epoch + 1) % 10 == 0:
                avg = total_loss / len(loader)
                logger.info("AE epoch %d/%d — loss=%.6f", epoch + 1, epochs, avg)

        # Calibrate threshold on full training set
        errors = self._reconstruction_errors(X)
        licit_errors = errors[y == 0]
        self._threshold = float(licit_errors.mean() + self._threshold_k * licit_errors.std())
        logger.info(
            "autoencoder threshold calibrated: %.6f (k=%.1f, licit mean=%.6f std=%.6f)",
            self._threshold, self._threshold_k, licit_errors.mean(), licit_errors.std(),
        )
        return self

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample MSE reconstruction errors."""
        try:
            import torch
        except ImportError as exc:
            raise ImportError("torch required") from exc

        device = next(self._model.parameters()).device  # type: ignore
        X_t = torch.tensor(X, dtype=torch.float32).to(device)

        self._model.eval()  # type: ignore
        with torch.no_grad():
            recon = self._model(X_t)  # type: ignore
            errors = ((X_t - recon) ** 2).mean(dim=1).cpu().numpy()
        return errors.astype(np.float32)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly score as P(fraud) via sigmoid of (error - threshold).

        Columns: [P(licit), P(fraud)]
        """
        if self._model is None:
            raise RuntimeError("Autoencoder not fitted or loaded")

        errors = self._reconstruction_errors(X)
        threshold = self._threshold or float(errors.mean())

        # Sigmoid squash of deviation from threshold
        deviation = errors - threshold
        p_fraud = 1.0 / (1.0 + np.exp(-deviation * 10))  # scale=10 for sharper boundary
        p_licit = 1.0 - p_fraud
        return np.stack([p_licit, p_fraud], axis=1).astype(np.float32)

    def save(self, path: Path) -> None:
        try:
            import torch
        except ImportError:
            return
        if self._model is None:
            raise RuntimeError("model not fitted")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": self._model.state_dict(),
                "input_dim":   self._input_dim,
                "hidden_dims": self._hidden_dims,
                "dropout":     self._dropout,
                "threshold_k": self._threshold_k,
                "threshold":   self._threshold,
            },
            path,
        )
        logger.info("autoencoder saved → %s", path)

    def load(self, path: Path) -> "AutoencoderModel":
        try:
            import torch
        except ImportError as exc:
            raise ImportError("torch required to load Autoencoder") from exc

        ckpt = torch.load(Path(path), map_location="cpu")
        self._input_dim   = ckpt["input_dim"]
        self._hidden_dims = ckpt["hidden_dims"]
        self._dropout     = ckpt["dropout"]
        self._threshold_k = ckpt["threshold_k"]
        self._threshold   = ckpt["threshold"]
        self._build_model()
        self._model.load_state_dict(ckpt["state_dict"])  # type: ignore
        self._model.eval()  # type: ignore
        logger.info("autoencoder loaded ← %s", path)
        return self
