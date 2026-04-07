"""
Model registry — loads and caches trained model artefacts from disk.

Expected artifact layout (set via Settings.model_artifact_path):
  ./ml/artifacts/
    random_forest_model.pkl
    xgboost_model.pkl
    lightgbm_model.pkl
    gnn_model.pt          (optional)
    autoencoder_model.pt  (optional)
    ensemble.json         (weight metadata)

Thread-safety: models are loaded once at startup and then read-only.
Hot-reload is triggered by the TTL check in _maybe_reload().
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Optional

from ml.models.autoencoder import AutoencoderModel
from ml.models.base import FraudModel
from ml.models.ensemble import EnsembleModel
from ml.models.gnn_model import GNNFraudModel
from ml.models.lightgbm_model import LightGBMModel
from ml.models.random_forest import RandomForestModel
from ml.models.xgboost_model import XGBoostModel

logger = logging.getLogger(__name__)

# Map logical name → (model_class, artifact_filename)
_MODEL_REGISTRY: dict[str, tuple[type, str]] = {
    "random_forest": (RandomForestModel, "random_forest_model.pkl"),
    "xgboost":       (XGBoostModel,      "xgboost_model.pkl"),
    "lightgbm":      (LightGBMModel,     "lightgbm_model.pkl"),
    "gnn":           (GNNFraudModel,     "gnn_model.pt"),
    "autoencoder":   (AutoencoderModel,  "autoencoder_model.pt"),
}


class ModelRegistry:
    """Thread-safe model registry with TTL-based hot-reload."""

    def __init__(self, artifact_dir: str, cache_ttl_s: int = 300) -> None:
        self._artifact_dir = Path(artifact_dir)
        self._cache_ttl_s  = cache_ttl_s
        self._models: dict[str, FraudModel] = {}
        self._ensemble: Optional[EnsembleModel] = None
        self._loaded_at: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def load_all(self) -> None:
        """Load all available model artefacts from the artifact directory.

        Silently skips models whose .pkl / .pt file is missing (e.g., optional GNN).
        """
        with self._lock:
            self._load_all_unsafe()

    def get(self, model_name: str) -> FraudModel:
        """Return a loaded model by name.  Hot-reloads if TTL has expired.

        Args:
            model_name: One of "random_forest", "xgboost", "lightgbm",
                        "gnn", "autoencoder", "ensemble".

        Raises:
            KeyError: If the model is not loaded.
        """
        self._maybe_reload()
        with self._lock:
            if model_name == "ensemble":
                if self._ensemble is None:
                    raise KeyError("ensemble model not available")
                return self._ensemble
            if model_name not in self._models:
                raise KeyError(f"model '{model_name}' not loaded")
            return self._models[model_name]

    def available_models(self) -> list[str]:
        """Return names of all currently loaded models."""
        with self._lock:
            names = list(self._models.keys())
            if self._ensemble is not None:
                names.append("ensemble")
            return names

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _maybe_reload(self) -> None:
        if time.monotonic() - self._loaded_at > self._cache_ttl_s:
            with self._lock:
                if time.monotonic() - self._loaded_at > self._cache_ttl_s:
                    logger.info("model registry TTL expired — reloading artefacts")
                    self._load_all_unsafe()

    def _load_all_unsafe(self) -> None:
        """Must be called with self._lock held."""
        loaded: dict[str, FraudModel] = {}

        for name, (cls, filename) in _MODEL_REGISTRY.items():
            path = self._artifact_dir / filename
            if not path.exists():
                logger.debug("skipping %s — artefact not found at %s", name, path)
                continue
            try:
                model_instance = cls()
                model_instance.load(path)
                loaded[name] = model_instance
                logger.info("loaded model: %s ← %s", name, path)
            except Exception as exc:
                logger.error("failed to load model %s: %s", name, exc, exc_info=True)

        # Build ensemble from whatever tree models are available
        tree_models = {k: v for k, v in loaded.items() if k in ("random_forest", "xgboost", "lightgbm")}
        if tree_models:
            ensemble_path = self._artifact_dir / "ensemble.json"
            ensemble = EnsembleModel(models=tree_models)
            if ensemble_path.exists():
                try:
                    ensemble.load(ensemble_path)
                    logger.info("loaded ensemble weights ← %s", ensemble_path)
                except Exception as exc:
                    logger.warning("could not load ensemble metadata: %s", exc)
            self._ensemble = ensemble
        else:
            self._ensemble = None

        self._models = loaded
        self._loaded_at = time.monotonic()
        logger.info(
            "registry ready: %d base models + ensemble=%s",
            len(loaded),
            "yes" if self._ensemble else "no",
        )
