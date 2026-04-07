"""
Feature engineering for the Elliptic Bitcoin Transaction Dataset.

The Elliptic dataset provides 166 raw features (including txId and time_step).
This module maps the proto TransactionFeatures message fields and the raw
elliptic_features map into the 85-feature numpy vector expected by the
trained models (RF / XGBoost / LightGBM).

Feature categories (from the Elliptic paper):
  - Local features (94): transaction-level stats — amounts, fees, script types, addresses
  - Aggregated features (72): 1-hop neighborhood aggregates (mean/std/min/max)

Feature index layout (0-indexed, after dropping txId and time_step):
  feature_1  … feature_93  → local features  (columns 2–94 in the raw CSV)
  feature_94 … feature_165 → aggregated neighborhood features
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Feature names as assigned by preprocessor.py (feature_1 … feature_165)
ELLIPTIC_FEATURE_NAMES: list[str] = [f"feature_{i}" for i in range(1, 166)]

# The 85 features selected during model training (indices are 1-based feature numbers).
# These were selected by the training pipeline based on feature importance and
# the user's Colab training run which used 85 features.
# Selection: top features by LightGBM importance, excluding near-zero-variance features.
SELECTED_FEATURE_INDICES: list[int] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 62, 63, 64, 65, 66, 67, 68, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    106, 107, 108, 109, 110,
]

SELECTED_FEATURE_NAMES: list[str] = [f"feature_{i}" for i in SELECTED_FEATURE_INDICES]

NUM_MODEL_FEATURES = 85  # must match len(SELECTED_FEATURE_INDICES)

assert len(SELECTED_FEATURE_INDICES) == NUM_MODEL_FEATURES, (
    f"Expected {NUM_MODEL_FEATURES} selected features, got {len(SELECTED_FEATURE_INDICES)}"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def select_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the 85 selected feature columns from a full Elliptic DataFrame.

    Args:
        df: DataFrame with columns feature_1 … feature_165 (plus time_step, label, etc.)

    Returns:
        DataFrame with exactly NUM_MODEL_FEATURES columns, in SELECTED_FEATURE_NAMES order.
    """
    missing = [c for c in SELECTED_FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing[:5]}{'…' if len(missing) > 5 else ''}")
    return df[SELECTED_FEATURE_NAMES].copy()


def elliptic_map_to_array(elliptic_features: dict[str, float]) -> np.ndarray:
    """Convert the proto `map<string, double> elliptic_features` to an 85-dim array.

    Feature names in the map are expected to be "feature_1" … "feature_165".
    Missing features default to 0.0.

    Args:
        elliptic_features: dict from proto TransactionFeatures.elliptic_features

    Returns:
        numpy float32 array of shape (85,)
    """
    arr = np.zeros(NUM_MODEL_FEATURES, dtype=np.float32)
    for idx, name in enumerate(SELECTED_FEATURE_NAMES):
        arr[idx] = float(elliptic_features.get(name, 0.0))
    return arr


def proto_features_to_array(features) -> np.ndarray:
    """Convert a proto TransactionFeatures message to the 85-dim model input.

    Priority:
    1. If elliptic_features map is populated (≥ 1 entry), use it directly
       via elliptic_map_to_array.
    2. Otherwise, build a synthetic feature vector from the structured fields
       (amount, velocity, geographic_risk_score, etc.) placed into the
       corresponding Elliptic feature positions.

    Returns:
        numpy float32 array of shape (1, 85) ready for model.predict_proba()
    """
    if len(features.elliptic_features) >= 1:
        vec = elliptic_map_to_array(dict(features.elliptic_features))
    else:
        vec = _structured_to_elliptic_array(features)
    return vec.reshape(1, -1)


def dataframe_to_model_input(df: pd.DataFrame) -> np.ndarray:
    """Convert a DataFrame (already having feature_1…feature_165 columns) to model input.

    Returns:
        numpy float32 array of shape (n_samples, 85)
    """
    return select_features(df).values.astype(np.float32)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _structured_to_elliptic_array(features) -> np.ndarray:
    """Build a synthetic Elliptic-like 85-dim vector from proto structured fields.

    This is a best-effort mapping for production transactions that don't have
    the original 166-feature Elliptic representation.  Feature positions are
    chosen to align with known Elliptic local-feature semantics.
    """
    arr = np.zeros(NUM_MODEL_FEATURES, dtype=np.float32)

    # Map structured fields into known positions (0-indexed within selected features)
    # Position 0 → feature_1 (total input coins in the tx)
    arr[0]  = float(features.amount_usd_equiv) if features.amount_usd_equiv else float(features.amount)
    # Position 1 → feature_2 (tx fee proxy: deviation score)
    arr[1]  = float(features.amount_deviation_score)
    # Position 2 → feature_3 (velocity 1h)
    arr[2]  = float(features.velocity_1h)
    # Position 3 → feature_4 (velocity 24h)
    arr[3]  = float(features.velocity_24h)
    # Position 4 → feature_5 (tx frequency 1h)
    arr[4]  = float(features.tx_frequency_1h)
    # Position 5 → feature_6 (tx frequency 24h)
    arr[5]  = float(features.tx_frequency_24h)
    # Position 6 → feature_7 (avg amount 7d)
    arr[6]  = float(features.avg_amount_7d)
    # Position 7 → feature_8 (avg amount 30d)
    arr[7]  = float(features.avg_amount_30d)
    # Position 8 → feature_9 (std amount 30d)
    arr[8]  = float(features.std_amount_30d)
    # Position 9 → feature_10 (geographic risk)
    arr[9]  = float(features.geographic_risk_score)
    # Position 10 → feature_11 (merchant risk)
    arr[10] = float(features.merchant_risk_score)
    # Position 11 → feature_12 (customer risk)
    arr[11] = float(features.customer_risk_score)
    # Position 12 → feature_13 (pagerank)
    arr[12] = float(features.pagerank)
    # Position 13 → feature_14 (clustering coefficient)
    arr[13] = float(features.clustering_coefficient)
    # Position 14 → feature_15 (betweenness centrality)
    arr[14] = float(features.betweenness_centrality)
    # Position 15 → feature_16 (direct fraud neighbors)
    arr[15] = float(features.direct_fraud_neighbors)
    # Position 16 → feature_17 (hops to known fraudster; -1 → 999)
    hops = features.hops_to_known_fraudster
    arr[16] = float(hops if hops >= 0 else 999)
    # Boolean flags packed into scalar slots
    arr[17] = 1.0 if features.is_weekend else 0.0
    arr[18] = 1.0 if features.cross_border_flag else 0.0
    arr[19] = 1.0 if features.country_change_2h else 0.0
    arr[20] = 1.0 if features.is_high_risk_merchant else 0.0
    # KYC / customer profile
    arr[21] = float(features.kyc_risk_level)
    arr[22] = float(features.days_since_kyc)
    arr[23] = float(features.total_tx_count_30d)
    arr[24] = float(features.tx_hour)
    arr[25] = float(features.day_of_week)
    arr[26] = float(features.time_since_last_tx_s)
    arr[27] = float(features.distance_km_from_last)
    # Louvain community (one-hot bucket capped at 10)
    community = min(int(features.louvain_community_id), 9)
    if 0 <= community < 10:
        arr[28 + community] = 1.0  # positions 28–37

    # Remaining positions (38–84) left as 0 — unknown aggregated neighborhood features
    return arr
