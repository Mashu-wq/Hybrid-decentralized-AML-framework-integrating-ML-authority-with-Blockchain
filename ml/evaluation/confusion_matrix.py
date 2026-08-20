"""
Confusion-matrix visualisation for the fraud-detection models.

Two modes:

  1. --recompute   Load the trained artefacts from ``ml/artifacts/`` and run
                   them against the real Elliptic test split, then plot the
                   confusion matrix for each. This is the honest, reproducible
                   path for the thesis (requires the dataset — ``make seed-ml``).

  2. (default)     Plot straight from the stored ``COLAB_BENCHMARK`` counts in
                   ``ml.evaluation.evaluator`` — no dataset needed. Useful when
                   you just want the figure from the numbers already reported.

Outputs (written to ``ml/evaluation/results/``):
  - confusion_matrix_<model>.png   one 2x2 matrix per model (counts + %)
  - confusion_matrix_grid.png      all models on a single figure

Usage:
  python -m ml.evaluation.confusion_matrix                 # from benchmark counts
  python -m ml.evaluation.confusion_matrix --recompute     # from real artefacts
  python -m ml.evaluation.confusion_matrix --recompute --threshold 0.5
"""
from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # headless — write PNGs without a display
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix

from ml.evaluation.evaluator import COLAB_BENCHMARK, EvalMetrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths & class labels
# ---------------------------------------------------------------------------

RESULTS_DIR = Path(__file__).parent / "results"
ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "ml" / "artifacts"

CLASS_LABELS = ["Licit (0)", "Fraud (1)"]  # rows = actual, cols = predicted

# Artefact filename + loader spec for the --recompute path.
# Each entry: (model_name, artefact_filename, factory) where factory() builds an
# unfitted model instance ready for .load().
def _model_specs() -> list[tuple[str, str, "callable"]]:
    from ml.models.random_forest import RandomForestModel
    from ml.models.xgboost_model import XGBoostModel
    from ml.models.lightgbm_model import LightGBMModel
    from ml.models.autoencoder import AutoencoderModel
    from ml.models.gnn_model import GNNFraudModel

    return [
        ("lightgbm",      "lightgbm_model.pkl",      lambda: LightGBMModel()),
        ("random_forest", "random_forest_model.pkl", lambda: RandomForestModel()),
        ("xgboost",       "xgboost_model.pkl",       lambda: XGBoostModel()),
        ("gnn",           "gnn_model.pt",            lambda: GNNFraudModel()),
        # Elliptic dataset → fraud has LOWER reconstruction error (see CLAUDE.md).
        ("autoencoder",   "autoencoder_model.pt",    lambda: AutoencoderModel(inverted=True)),
    ]


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

def plot_confusion_matrix(
    cm: np.ndarray,
    model_name: str,
    ax: Optional[plt.Axes] = None,
    title_suffix: str = "",
) -> plt.Axes:
    """Draw one 2x2 confusion matrix as an annotated heatmap.

    Each cell shows the raw count and its share of the true-class row, so an
    imbalanced test set (fraud is ~5%) stays readable.

    Args:
        cm:         2x2 array [[TN, FP], [FN, TP]] (sklearn label order [0, 1]).
        model_name: Used in the title.
        ax:         Optional axis to draw into (for grid layouts).
        title_suffix: Extra text appended to the title (e.g. metrics).

    Returns:
        The axis drawn onto.
    """
    if ax is None:
        _, ax = plt.subplots(figsize=(5.2, 4.4))

    row_sums = cm.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1  # avoid divide-by-zero
    cm_pct = cm / row_sums

    annot = np.empty_like(cm, dtype=object)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            annot[i, j] = f"{cm[i, j]:,}\n{cm_pct[i, j] * 100:.1f}%"

    sns.heatmap(
        cm,
        annot=annot,
        fmt="",
        cmap="Blues",
        cbar=False,
        square=True,
        linewidths=0.5,
        linecolor="white",
        xticklabels=CLASS_LABELS,
        yticklabels=CLASS_LABELS,
        annot_kws={"fontsize": 11},
        ax=ax,
    )
    ax.set_xlabel("Predicted label", fontsize=10)
    ax.set_ylabel("Actual label", fontsize=10)
    title = model_name.replace("_", " ").title()
    if title_suffix:
        title += f"\n{title_suffix}"
    ax.set_title(title, fontsize=12, fontweight="bold")
    return ax


def _metrics_suffix(cm: np.ndarray) -> str:
    """Short precision/recall/F1 caption computed from the matrix itself."""
    tn, fp, fn, tp = cm.ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return f"P={precision:.2f}  R={recall:.2f}  F1={f1:.2f}"


def save_single(cm: np.ndarray, model_name: str) -> Path:
    """Render + save one confusion matrix PNG for a model."""
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    plot_confusion_matrix(cm, model_name, ax=ax, title_suffix=_metrics_suffix(cm))
    fig.tight_layout()
    out = RESULTS_DIR / f"confusion_matrix_{model_name}.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("wrote %s", out)
    return out


def save_grid(matrices: dict[str, np.ndarray]) -> Path:
    """Render all models onto one figure grid."""
    n = len(matrices)
    ncols = min(3, n)
    nrows = math.ceil(n / ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(5.0 * ncols, 4.6 * nrows))
    axes = np.atleast_1d(axes).ravel()

    for ax, (name, cm) in zip(axes, matrices.items()):
        plot_confusion_matrix(cm, name, ax=ax, title_suffix=_metrics_suffix(cm))
    for ax in axes[n:]:  # hide any unused cells
        ax.axis("off")

    fig.suptitle("Confusion Matrices — Fraud Detection Models (Elliptic test set)",
                 fontsize=15, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    out = RESULTS_DIR / "confusion_matrix_grid.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("wrote %s", out)
    return out


# ---------------------------------------------------------------------------
# Matrix sources
# ---------------------------------------------------------------------------

def cm_from_metrics(m: EvalMetrics) -> np.ndarray:
    """Build a [[TN, FP], [FN, TP]] matrix from stored EvalMetrics counts.

    Some benchmark rows store TN=0 as a placeholder; reconstruct it from the
    sample count when the other three cells are present.
    """
    tn = m.true_negatives
    if tn == 0 and m.sample_count > 0:
        tn = m.sample_count - m.true_positives - m.false_positives - m.false_negatives
        tn = max(tn, 0)
    return np.array([[tn, m.false_positives],
                     [m.false_negatives, m.true_positives]], dtype=np.int64)


def matrices_from_benchmark() -> dict[str, np.ndarray]:
    """Confusion matrices from the stored Colab benchmark (no dataset needed)."""
    return {m.model_name: cm_from_metrics(m) for m in COLAB_BENCHMARK.models}


def matrices_from_artifacts(threshold: float = 0.5) -> dict[str, np.ndarray]:
    """Recompute confusion matrices by running trained artefacts on the test set.

    Requires the Elliptic dataset (``make seed-ml``) and the trained artefacts
    in ``ml/artifacts/``.
    """
    from ml.data.preprocessor import load_and_preprocess
    from ml.features.engineering import SELECTED_FEATURE_INDICES

    logger.info("loading + preprocessing Elliptic dataset …")
    # Neural nets (GNN/autoencoder) train on scaled inputs; the artefacts were
    # trained without preprocessor-level scaling, so keep scaling off here to
    # match the training pipeline. SMOTE only affects the train split.
    ds = load_and_preprocess(apply_smote=False, apply_scaling=False)

    # preprocessor returns feature_1 … feature_165 in order, so 1-based feature
    # number k lives at column k-1. Slice down to the 85 model features.
    col_idx = [k - 1 for k in SELECTED_FEATURE_INDICES]
    X_test = ds.X_test[:, col_idx]
    y_test = ds.y_test
    logger.info("test set: %d samples, %d fraud, %d features",
                len(y_test), int(y_test.sum()), X_test.shape[1])

    matrices: dict[str, np.ndarray] = {}
    for name, filename, factory in _model_specs():
        path = ARTIFACT_DIR / filename
        if not path.exists():
            logger.warning("skipping %s — artefact not found at %s", name, path)
            continue
        try:
            model = factory().load(path)
            proba = model.predict_proba(X_test)[:, 1]
            y_pred = (proba >= threshold).astype(np.int32)
            cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
            matrices[name] = cm
            tn, fp, fn, tp = cm.ravel()
            logger.info("%-14s TN=%d FP=%d FN=%d TP=%d", name, tn, fp, fn, tp)
        except Exception as exc:  # noqa: BLE001 — keep going for the other models
            logger.error("failed to evaluate %s: %s", name, exc)
    return matrices


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Plot confusion matrices for fraud models.")
    parser.add_argument("--recompute", action="store_true",
                        help="Run trained artefacts on the real test set (needs the dataset).")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Fraud probability cut-off (default 0.5).")
    parser.add_argument("--no-grid", action="store_true", help="Skip the combined grid figure.")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.recompute:
        matrices = matrices_from_artifacts(threshold=args.threshold)
        if not matrices:
            logger.error("no matrices produced — is the dataset seeded and are artefacts present?")
            return
    else:
        matrices = matrices_from_benchmark()
        logger.info("using stored COLAB_BENCHMARK counts (pass --recompute to run artefacts)")

    for name, cm in matrices.items():
        save_single(cm, name)
    if not args.no_grid:
        save_grid(matrices)

    logger.info("done — figures in %s", RESULTS_DIR)


if __name__ == "__main__":
    main()
