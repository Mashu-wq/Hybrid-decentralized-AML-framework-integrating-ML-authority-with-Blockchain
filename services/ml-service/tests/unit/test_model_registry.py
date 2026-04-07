"""
Unit tests for ModelRegistry — covers loading, hot-reload TTL, and fallback handling.
"""
from __future__ import annotations

import os
import pickle
import tempfile
import time
from pathlib import Path

import numpy as np
import pytest

from app.models.registry import ModelRegistry
from ml.models.random_forest import RandomForestModel
from ml.models.lightgbm_model import LightGBMModel
from ml.models.ensemble import EnsembleModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _train_and_save_rf(artifact_dir: Path) -> None:
    """Train a tiny RF and save to artifact_dir/random_forest_model.pkl."""
    X = np.random.rand(200, 85).astype(np.float32)
    y = np.array([0] * 180 + [1] * 20)
    model = RandomForestModel(params={"n_estimators": 5, "random_state": 42})
    model.fit(X, y)
    model.save(artifact_dir / "random_forest_model.pkl")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_registry_empty_dir():
    """Registry with no artifacts should load 0 models without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        registry = ModelRegistry(artifact_dir=tmpdir)
        registry.load_all()
        assert registry.available_models() == []


def test_registry_get_missing_model():
    with tempfile.TemporaryDirectory() as tmpdir:
        registry = ModelRegistry(artifact_dir=tmpdir)
        registry.load_all()
        with pytest.raises(KeyError, match="not loaded"):
            registry.get("random_forest")


def test_registry_loads_rf_model():
    """After saving an RF model, the registry should load and return it."""
    pytest.importorskip("sklearn")

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir)
        _train_and_save_rf(artifact_dir)

        registry = ModelRegistry(artifact_dir=str(artifact_dir))
        registry.load_all()

        assert "random_forest" in registry.available_models()
        assert "ensemble" in registry.available_models()

        model = registry.get("random_forest")
        X = np.random.rand(5, 85).astype(np.float32)
        proba = model.predict_proba(X)
        assert proba.shape == (5, 2)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)


def test_registry_ensemble_built_from_tree_models():
    """Ensemble should be available when at least one tree model is loaded."""
    pytest.importorskip("sklearn")

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir)
        _train_and_save_rf(artifact_dir)

        registry = ModelRegistry(artifact_dir=str(artifact_dir))
        registry.load_all()

        ensemble = registry.get("ensemble")
        assert isinstance(ensemble, EnsembleModel)
        assert "random_forest" in ensemble._models


def test_registry_predict_proba_shape():
    pytest.importorskip("sklearn")

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir)
        _train_and_save_rf(artifact_dir)

        registry = ModelRegistry(artifact_dir=str(artifact_dir))
        registry.load_all()

        model = registry.get("ensemble")
        X = np.random.rand(10, 85).astype(np.float32)
        proba = model.predict_proba(X)
        assert proba.shape == (10, 2)


def test_registry_ttl_triggers_reload():
    """After TTL expires, registry should reload (no error)."""
    pytest.importorskip("sklearn")

    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_dir = Path(tmpdir)
        _train_and_save_rf(artifact_dir)

        # TTL of 0 seconds → every get() reloads
        registry = ModelRegistry(artifact_dir=str(artifact_dir), cache_ttl_s=0)
        registry.load_all()

        # Force TTL expiry
        registry._loaded_at = 0.0

        model = registry.get("random_forest")
        assert model is not None


def test_registry_skips_corrupt_artifact(caplog):
    """Registry should skip a corrupt artifact and log an error (not raise)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        corrupt_path = Path(tmpdir) / "random_forest_model.pkl"
        corrupt_path.write_bytes(b"not a valid pickle")

        registry = ModelRegistry(artifact_dir=tmpdir)
        import logging
        with caplog.at_level(logging.ERROR):
            registry.load_all()

        # Should not have loaded the corrupt model
        assert "random_forest" not in registry.available_models()
        assert any("failed to load model" in r.message for r in caplog.records)
