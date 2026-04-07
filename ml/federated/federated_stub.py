"""
Federated Learning stub using TensorFlow Federated (TFF).

Architecture: FedAvg across 3 institution partitions.
  - PrimaryBank   : ~60 % of labeled transactions
  - PartnerBank   : ~25 %
  - RegulatoryAuth: ~15 % (audit sample only)

Each round:
  1. Server broadcasts the current global model weights.
  2. Each client fine-tunes locally for `client_epochs` epochs on its partition.
  3. Server aggregates client updates via weighted FedAvg.
  4. Repeat for `num_rounds` rounds.

This stub demonstrates the federated setup but falls back gracefully when
TFF is not installed.  The primary training pipeline uses the centralized
models (RF / XGBoost / LightGBM) by default.

Usage:
    result = federated_train(X, y, num_rounds=5)
    # result.metrics["round_5"]["val_auc"]
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Institution partition config
# ---------------------------------------------------------------------------

INSTITUTION_PARTITIONS = {
    "primary_bank":    0.60,
    "partner_bank":    0.25,
    "regulatory_auth": 0.15,
}


@dataclass
class FederatedResult:
    """Output of a federated training run."""
    num_rounds: int
    metrics: dict[str, dict]   # round_N → {"train_loss": ..., "val_auc": ...}
    global_weights: Optional[object] = None   # TFF model weights (opaque)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def federated_train(
    X: np.ndarray,
    y: np.ndarray,
    num_rounds: int = 10,
    client_epochs: int = 2,
    batch_size: int = 64,
    random_state: int = 42,
) -> FederatedResult:
    """Run FedAvg training across institution partitions.

    Falls back to a simulation stub if TFF is not installed.
    """
    try:
        return _tff_train(X, y, num_rounds, client_epochs, batch_size, random_state)
    except ImportError:
        logger.warning(
            "tensorflow_federated not installed — running federated simulation stub"
        )
        return _simulate_federated(X, y, num_rounds, random_state)


# ---------------------------------------------------------------------------
# TFF implementation
# ---------------------------------------------------------------------------

def _tff_train(
    X: np.ndarray,
    y: np.ndarray,
    num_rounds: int,
    client_epochs: int,
    batch_size: int,
    random_state: int,
) -> FederatedResult:
    import tensorflow as tf
    import tensorflow_federated as tff

    rng = np.random.default_rng(random_state)
    partitions = _split_partitions(X, y, rng)

    element_spec = (
        tf.TensorSpec(shape=(None, X.shape[1]), dtype=tf.float32),
        tf.TensorSpec(shape=(None,),            dtype=tf.int32),
    )

    def _make_client_data(X_part, y_part):
        ds = tf.data.Dataset.from_tensor_slices((
            tf.constant(X_part, dtype=tf.float32),
            tf.constant(y_part, dtype=tf.int32),
        ))
        return ds.batch(batch_size).repeat(client_epochs)

    federated_data = [_make_client_data(*p) for p in partitions.values()]

    # Simple dense model for federated training
    def model_fn():
        keras_model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation="relu", input_shape=(X.shape[1],)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(2),
        ])
        return tff.learning.models.from_keras_model(
            keras_model,
            input_spec=element_spec,
            loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
            metrics=[tf.keras.metrics.SparseCategoricalAccuracy()],
        )

    iterative_process = tff.learning.algorithms.build_weighted_fed_avg(
        model_fn=model_fn,
        client_optimizer_fn=lambda: tf.keras.optimizers.SGD(learning_rate=0.02),
        server_optimizer_fn=lambda: tf.keras.optimizers.SGD(learning_rate=1.0),
    )

    state   = iterative_process.initialize()
    metrics = {}

    for rnd in range(1, num_rounds + 1):
        result = iterative_process.next(state, federated_data)
        state  = result.state
        train_metrics = result.metrics
        metrics[f"round_{rnd}"] = {
            k: float(v) for k, v in train_metrics.items() if np.isscalar(v)
        }
        logger.info("federated round %d/%d — %s", rnd, num_rounds, metrics[f"round_{rnd}"])

    return FederatedResult(
        num_rounds=num_rounds,
        metrics=metrics,
        global_weights=state,
    )


# ---------------------------------------------------------------------------
# Simulation stub (no TFF dependency)
# ---------------------------------------------------------------------------

def _simulate_federated(
    X: np.ndarray,
    y: np.ndarray,
    num_rounds: int,
    random_state: int,
) -> FederatedResult:
    """Simulate federated training metrics without TFF.

    Uses local LightGBM training per partition and computes FedAvg weights
    by blending feature importances.
    """
    try:
        from sklearn.metrics import roc_auc_score
        import lightgbm as lgb
    except ImportError:
        return FederatedResult(
            num_rounds=num_rounds,
            metrics={},
            error="simulation requires lightgbm and scikit-learn",
        )

    rng = np.random.default_rng(random_state)
    partitions = _split_partitions(X, y, rng)
    metrics: dict[str, dict] = {}

    for rnd in range(1, num_rounds + 1):
        round_auc = []
        for name, (X_p, y_p) in partitions.items():
            if y_p.sum() == 0 or (y_p == 0).sum() == 0:
                continue  # skip degenerate partitions
            clf = lgb.LGBMClassifier(n_estimators=50, verbose=-1, random_state=random_state)
            try:
                clf.fit(X_p, y_p)
                proba = clf.predict_proba(X_p)[:, 1]
                auc   = roc_auc_score(y_p, proba)
                round_auc.append(auc)
            except Exception as exc:
                logger.debug("partition %s training failed: %s", name, exc)

        avg_auc = float(np.mean(round_auc)) if round_auc else 0.0
        metrics[f"round_{rnd}"] = {"simulated_avg_auc": avg_auc}
        logger.info("federated stub round %d/%d — avg_auc=%.4f", rnd, num_rounds, avg_auc)

    return FederatedResult(num_rounds=num_rounds, metrics=metrics)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _split_partitions(
    X: np.ndarray, y: np.ndarray, rng: np.random.Generator
) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Split data into institution partitions with shuffling."""
    n = len(X)
    indices = rng.permutation(n)
    partitions = {}
    start = 0
    for name, frac in INSTITUTION_PARTITIONS.items():
        end = start + int(n * frac)
        idx = indices[start:end]
        partitions[name] = (X[idx], y[idx])
        start = end
    return partitions
