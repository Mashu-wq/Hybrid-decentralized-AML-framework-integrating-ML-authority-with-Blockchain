"""
Model evaluation utilities for fraud detection.

Computes a full set of classification metrics:
  - Precision, Recall, F1, Accuracy
  - ROC-AUC, PR-AUC
  - Confusion matrix (TP / FP / TN / FN)
  - Average prediction latency

Also provides a comparison table across all registered models matching the
training report format (used for GetModelComparison RPC).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.models.base import FraudModel

logger = logging.getLogger(__name__)


@dataclass
class EvalMetrics:
    """Full evaluation result for one model on one test set."""
    model_name:     str
    model_version:  str

    precision:      float
    recall:         float
    f1_score:       float
    accuracy:       float
    auc_roc:        float
    auc_pr:         float

    true_positives:  int
    false_positives: int
    true_negatives:  int
    false_negatives: int
    sample_count:    int

    avg_latency_ms:  float = 0.0
    p95_latency_ms:  float = 0.0

    threshold:       float = 0.5
    period:          str   = "test"

    @property
    def f1_at_threshold(self) -> float:
        return self.f1_score


@dataclass
class ModelComparisonReport:
    """Side-by-side comparison of all evaluated models."""
    models:       list[EvalMetrics]
    active_model: str = "ensemble"

    def best_by(self, metric: str = "auc_roc") -> EvalMetrics:
        return max(self.models, key=lambda m: getattr(m, metric, 0.0))

    def to_dict_list(self) -> list[dict]:
        rows = []
        for m in self.models:
            rows.append({
                "model_name":       m.model_name,
                "precision":        round(m.precision, 4),
                "recall":           round(m.recall, 4),
                "f1_score":         round(m.f1_score, 4),
                "accuracy":         round(m.accuracy, 4),
                "auc_roc":          round(m.auc_roc, 4),
                "auc_pr":           round(m.auc_pr, 4),
                "tp":               m.true_positives,
                "fp":               m.false_positives,
                "tn":               m.true_negatives,
                "fn":               m.false_negatives,
                "avg_latency_ms":   round(m.avg_latency_ms, 2),
            })
        return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_model(
    model: FraudModel,
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
    model_version: str = "unknown",
    measure_latency: bool = True,
    latency_samples: int = 200,
) -> EvalMetrics:
    """Evaluate a single model on the test set.

    Args:
        model:           Any FraudModel instance (must be fitted/loaded).
        X_test:          Feature matrix (n_samples, n_features)
        y_test:          Ground truth labels (n_samples,)
        threshold:       Fraud probability cut-off.
        model_version:   Version string for the report (e.g. "v1.0.0")
        measure_latency: If True, time predictions on a sample subset.
        latency_samples: Number of samples to time for latency measurement.

    Returns:
        EvalMetrics with full metric suite.
    """
    proba = model.predict_proba(X_test)[:, 1]
    y_pred = (proba >= threshold).astype(np.int32)

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall    = float(recall_score(y_test, y_pred, zero_division=0))
    f1        = float(f1_score(y_test, y_pred, zero_division=0))
    accuracy  = float(accuracy_score(y_test, y_pred))

    try:
        auc_roc = float(roc_auc_score(y_test, proba))
    except ValueError:
        auc_roc = 0.0

    try:
        auc_pr = float(average_precision_score(y_test, proba))
    except ValueError:
        auc_pr = 0.0

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Latency measurement
    avg_lat = p95_lat = 0.0
    if measure_latency and len(X_test) > 0:
        n_lat  = min(latency_samples, len(X_test))
        X_lat  = X_test[:n_lat]
        lats   = []
        for i in range(n_lat):
            t0 = time.perf_counter()
            model.predict_proba(X_lat[i:i+1])
            lats.append((time.perf_counter() - t0) * 1000)
        avg_lat = float(np.mean(lats))
        p95_lat = float(np.percentile(lats, 95))

    metrics = EvalMetrics(
        model_name=model.model_name,
        model_version=model_version,
        precision=precision,
        recall=recall,
        f1_score=f1,
        accuracy=accuracy,
        auc_roc=auc_roc,
        auc_pr=auc_pr,
        true_positives=int(tp),
        false_positives=int(fp),
        true_negatives=int(tn),
        false_negatives=int(fn),
        sample_count=len(y_test),
        avg_latency_ms=avg_lat,
        p95_latency_ms=p95_lat,
        threshold=threshold,
    )

    logger.info(
        "%-16s precision=%.4f recall=%.4f f1=%.4f roc_auc=%.4f pr_auc=%.4f "
        "tp=%d fp=%d tn=%d fn=%d lat_avg=%.2fms",
        model.model_name,
        precision, recall, f1, auc_roc, auc_pr,
        tp, fp, tn, fn, avg_lat,
    )
    return metrics


def compare_models(
    models: list[FraudModel],
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
    active_model: str = "ensemble",
) -> ModelComparisonReport:
    """Evaluate multiple models and build a comparison report.

    Args:
        models:       List of fitted FraudModel instances.
        X_test, y_test: Shared test set.
        threshold:    Decision boundary (same for all models).
        active_model: Name of the currently deployed champion.

    Returns:
        ModelComparisonReport with a metrics list sorted by ROC-AUC desc.
    """
    results = [evaluate_model(m, X_test, y_test, threshold=threshold) for m in models]
    results.sort(key=lambda m: m.auc_roc, reverse=True)
    return ModelComparisonReport(models=results, active_model=active_model)


# ---------------------------------------------------------------------------
# Known benchmark — AUTHORITATIVE: the training-report run of 2026-07-07.
# Elliptic Bitcoin Dataset, 80/20 temporal split (49 time steps: 1–39 train,
# 40–49 test), SMOTE on the training partition only.
#   train 36,921 (32,879 licit / 4,042 fraud) -> 49,318 after SMOTE
#   test   9,643 ( 9,140 licit /   503 fraud), prevalence 5.22%
# These are the numbers reported in the paper (Table IV). Do NOT edit them to
# match a figure in ml/evaluation/results/ — those PNGs are RENDERED FROM this
# table by confusion_matrix.py, so they are not an independent source. An
# earlier stale copy of this block (a 2026-06-08 run: 9,642 rows / 506 illicit)
# was propagated into the paper on exactly that mistaken reasoning.
# GNN: pure-PyTorch GraphSAGE (3-layer, 85→256→128→64→2), 50 epochs.
# Autoencoder: inverted scoring — fraud has LOWER reconstruction error on
#   the Elliptic dataset (fraud txs have simpler, more uniform features).
# GNN/autoencoder rows are from the earlier run (sample_count 9,313, graph
# models drop edge-less nodes) and are NOT covered by the 2026-07-07 report.
# ---------------------------------------------------------------------------

COLAB_BENCHMARK = ModelComparisonReport(
    active_model="ensemble",
    models=[
        EvalMetrics(
            model_name="lightgbm",      model_version="colab-v1",
            precision=0.6708, recall=0.6521, f1_score=0.6613,
            accuracy=0.9652, auc_roc=0.9633, auc_pr=0.7718,
            true_positives=328, false_positives=161, true_negatives=8979, false_negatives=175,
            sample_count=9643, threshold=0.5, period="test",
        ),
        EvalMetrics(
            model_name="random_forest", model_version="colab-v1",
            precision=0.8712, recall=0.5646, f1_score=0.6852,
            accuracy=0.9729, auc_roc=0.9605, auc_pr=0.7462,
            true_positives=284, false_positives=42, true_negatives=9098, false_negatives=219,
            sample_count=9643, threshold=0.5, period="test",
        ),
        EvalMetrics(
            model_name="xgboost",       model_version="colab-v1",
            precision=0.6652, recall=0.6083, f1_score=0.6355,
            accuracy=0.9636, auc_roc=0.9555, auc_pr=0.7374,
            true_positives=306, false_positives=154, true_negatives=8986, false_negatives=197,
            sample_count=9643, threshold=0.5, period="test",
        ),
        EvalMetrics(
            model_name="gnn",           model_version="colab-v1",
            precision=0.2234, recall=0.6645, f1_score=0.3344,
            accuracy=0.0, auc_roc=0.8886, auc_pr=0.547,
            true_positives=313, false_positives=1088, true_negatives=7754, false_negatives=158,
            sample_count=9313, threshold=0.5, period="test",
        ),
        EvalMetrics(
            model_name="autoencoder",   model_version="colab-v1",
            precision=0.0661, recall=0.6815, f1_score=0.1205,
            accuracy=0.0, auc_roc=0.7094, auc_pr=0.389,
            true_positives=321, false_positives=4534, true_negatives=4308, false_negatives=150,
            sample_count=9313, threshold=0.5, period="test",
        ),
    ],
)
