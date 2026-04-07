"""
Elliptic Bitcoin Transaction Dataset — preprocessing pipeline.

Dataset structure:
  elliptic_txs_features.csv  : 166 features per transaction (no header names)
  elliptic_txs_classes.csv   : label per tx  (1=illicit, 2=licit, unknown)
  elliptic_txs_edgelist.csv  : directed edges for graph models

Class distribution in labeled set:
  illicit   :  4,545  (9.7 %)
  licit     : 42,019  (90.3 %)
  unknown   :157,205  (discarded for supervised training)

Pipeline:
  1. Load and merge feature + class files
  2. Drop unknown labels — keep only labeled data
  3. Remap labels: 1→1 (fraud), 2→0 (legit)
  4. Temporal train/test split on time_step (first 70% → train, rest → test)
  5. Apply SMOTE to training set only
  6. Return (X_train, X_test, y_train, y_test, feature_names)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).parent / "raw"

FEATURES_FILE = DATA_DIR / "elliptic_txs_features.csv"
CLASSES_FILE  = DATA_DIR / "elliptic_txs_classes.csv"
EDGES_FILE    = DATA_DIR / "elliptic_txs_edgelist.csv"

# Elliptic column layout: txId, time_step, feature_1 … feature_165
NUM_ELLIPTIC_FEATURES = 166  # including txId and time_step
FEATURE_START_COL = 2        # feature_1 starts at column index 2

ILLICIT_LABEL = 1
LICIT_LABEL   = 2
UNKNOWN_LABEL = "unknown"

TRAIN_SPLIT_RATIO = 0.70  # first 70 time steps → train (temporal split)
SMOTE_RANDOM_STATE = 42


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProcessedDataset:
    X_train: np.ndarray
    X_test:  np.ndarray
    y_train: np.ndarray
    y_test:  np.ndarray
    feature_names: list[str]
    scaler:  Optional[StandardScaler]
    train_time_steps: list[int]
    test_time_steps:  list[int]
    class_distribution: dict[str, dict[str, int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_and_preprocess(
    features_path: Path = FEATURES_FILE,
    classes_path:  Path = CLASSES_FILE,
    apply_smote:   bool = True,
    apply_scaling: bool = False,
    smote_ratio:   float = 0.5,      # target minority/majority ratio after SMOTE
    random_state:  int = SMOTE_RANDOM_STATE,
) -> ProcessedDataset:
    """Full preprocessing pipeline for the Elliptic dataset.

    Args:
        features_path: Path to elliptic_txs_features.csv
        classes_path:  Path to elliptic_txs_classes.csv
        apply_smote:   Apply SMOTE oversampling to training set
        apply_scaling: Apply StandardScaler (tree models don't need it)
        smote_ratio:   Minority/majority ratio target for SMOTE
        random_state:  Random seed

    Returns:
        ProcessedDataset with split arrays, feature names, and scaler
    """
    logger.info("loading elliptic dataset from %s", features_path.parent)

    # 1. Load raw data
    features_df, classes_df = _load_raw(features_path, classes_path)

    # 2. Merge + filter
    df = _merge_and_filter(features_df, classes_df)
    logger.info("labeled samples: %d (fraud=%d, licit=%d)",
                len(df), (df["label"] == 1).sum(), (df["label"] == 0).sum())

    # 3. Temporal split
    feature_cols = [c for c in df.columns if c.startswith("feature_")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values.astype(np.int32)
    time_steps = df["time_step"].values

    all_steps = sorted(df["time_step"].unique())
    split_idx  = int(len(all_steps) * TRAIN_SPLIT_RATIO)
    train_steps = set(all_steps[:split_idx])
    test_steps  = set(all_steps[split_idx:])

    train_mask = np.array([ts in train_steps for ts in time_steps])
    test_mask  = ~train_mask

    X_train, y_train = X[train_mask], y[train_mask]
    X_test,  y_test  = X[test_mask],  y[test_mask]

    logger.info(
        "temporal split → train=%d samples (steps 1–%d), test=%d samples (steps %d–%d)",
        len(X_train), split_idx, len(X_test), split_idx + 1, len(all_steps),
    )

    # 4. SMOTE on training set only
    if apply_smote:
        fraud_count  = (y_train == 1).sum()
        licit_count  = (y_train == 0).sum()
        logger.info("before SMOTE: fraud=%d, licit=%d", fraud_count, licit_count)
        sampler = SMOTE(sampling_strategy=smote_ratio, random_state=random_state, n_jobs=-1)
        X_train, y_train = sampler.fit_resample(X_train, y_train)
        logger.info(
            "after  SMOTE: fraud=%d, licit=%d, synthetic=%d",
            (y_train == 1).sum(), (y_train == 0).sum(),
            (y_train == 1).sum() - fraud_count,
        )

    # 5. Optional scaling
    scaler: Optional[StandardScaler] = None
    if apply_scaling:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test  = scaler.transform(X_test)

    class_dist = {
        "train_original": {"fraud": int((y[train_mask] == 1).sum()), "licit": int((y[train_mask] == 0).sum())},
        "train_after_smote": {"fraud": int((y_train == 1).sum()), "licit": int((y_train == 0).sum())},
        "test": {"fraud": int((y_test == 1).sum()), "licit": int((y_test == 0).sum())},
    }

    return ProcessedDataset(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        feature_names=feature_cols,
        scaler=scaler,
        train_time_steps=sorted(train_steps),
        test_time_steps=sorted(test_steps),
        class_distribution=class_dist,
    )


def load_edge_list(edges_path: Path = EDGES_FILE) -> pd.DataFrame:
    """Load transaction edge list for graph model construction."""
    df = pd.read_csv(edges_path, header=None, names=["source", "target"])
    logger.info("edge list: %d edges", len(df))
    return df


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_raw(features_path: Path, classes_path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load raw CSV files and assign column names."""
    # Features: txId, time_step, feature_1 … feature_165
    feature_cols = ["txId", "time_step"] + [f"feature_{i}" for i in range(1, 166)]
    features_df = pd.read_csv(features_path, header=None, names=feature_cols)

    # Classes: txId, class (1=illicit, 2=licit, "unknown")
    classes_df = pd.read_csv(classes_path, names=["txId", "class_label"], header=0)

    return features_df, classes_df


def _merge_and_filter(features_df: pd.DataFrame, classes_df: pd.DataFrame) -> pd.DataFrame:
    """Merge features with labels, filter unknowns, remap labels."""
    df = features_df.merge(classes_df, on="txId", how="inner")

    # Filter out unknown labels
    df = df[df["class_label"] != UNKNOWN_LABEL].copy()
    df["class_label"] = df["class_label"].astype(int)

    # Remap: 1 (illicit) → 1 (fraud), 2 (licit) → 0 (legit)
    df["label"] = (df["class_label"] == ILLICIT_LABEL).astype(int)
    df = df.drop(columns=["class_label", "txId"])

    return df.sort_values("time_step").reset_index(drop=True)
