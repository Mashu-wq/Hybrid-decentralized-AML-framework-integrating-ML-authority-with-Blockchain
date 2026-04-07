"""
Unit tests for the feature pipeline and engineering module.
"""
from __future__ import annotations

import numpy as np
import pytest

from ml.features.engineering import (
    NUM_MODEL_FEATURES,
    SELECTED_FEATURE_NAMES,
    elliptic_map_to_array,
    select_features,
)
from app.features.pipeline import FeaturePipeline


# ---------------------------------------------------------------------------
# Tests for ml.features.engineering
# ---------------------------------------------------------------------------

def test_selected_feature_count():
    assert len(SELECTED_FEATURE_NAMES) == NUM_MODEL_FEATURES == 85


def test_elliptic_map_to_array_all_zeros():
    arr = elliptic_map_to_array({})
    assert arr.shape == (NUM_MODEL_FEATURES,)
    assert arr.dtype == np.float32
    assert np.all(arr == 0.0)


def test_elliptic_map_to_array_partial():
    arr = elliptic_map_to_array({"feature_1": 3.14, "feature_2": 2.71})
    assert arr[0] == pytest.approx(3.14, rel=1e-5)
    assert arr[1] == pytest.approx(2.71, rel=1e-5)
    # All other entries should be 0
    assert np.all(arr[2:] == 0.0)


def test_elliptic_map_to_array_ignores_unselected():
    # feature_166 doesn't exist; feature_200 doesn't exist
    arr = elliptic_map_to_array({"feature_200": 99.0, "feature_1": 1.0})
    assert arr[0] == pytest.approx(1.0)
    # 99.0 should not appear anywhere
    assert 99.0 not in arr


def test_select_features_basic():
    import pandas as pd

    columns = ["time_step", "label"] + [f"feature_{i}" for i in range(1, 166)]
    df = pd.DataFrame(np.random.rand(10, len(columns)), columns=columns)
    selected = select_features(df)
    assert selected.shape == (10, NUM_MODEL_FEATURES)
    assert list(selected.columns) == SELECTED_FEATURE_NAMES


def test_select_features_missing_column():
    import pandas as pd

    # Only first 10 features — missing most
    columns = ["time_step"] + [f"feature_{i}" for i in range(1, 11)]
    df = pd.DataFrame(np.zeros((5, len(columns))), columns=columns)
    with pytest.raises(ValueError, match="Missing feature columns"):
        select_features(df)


# ---------------------------------------------------------------------------
# Tests for FeaturePipeline
# ---------------------------------------------------------------------------

class _MockFeatures:
    """Minimal proto-like TransactionFeatures stub."""
    def __init__(self, elliptic=None):
        self.elliptic_features = elliptic or {}
        self.amount = 100.0
        self.amount_usd_equiv = 100.0
        self.amount_deviation_score = 0.0
        self.velocity_1h = 0.0
        self.velocity_24h = 0.0
        self.tx_frequency_1h = 0.0
        self.tx_frequency_24h = 0.0
        self.avg_amount_7d = 0.0
        self.avg_amount_30d = 0.0
        self.std_amount_30d = 0.0
        self.geographic_risk_score = 0.0
        self.merchant_risk_score = 0.0
        self.customer_risk_score = 0.0
        self.pagerank = 0.0
        self.clustering_coefficient = 0.0
        self.betweenness_centrality = 0.0
        self.direct_fraud_neighbors = 0
        self.hops_to_known_fraudster = -1
        self.is_weekend = False
        self.cross_border_flag = False
        self.country_change_2h = False
        self.is_high_risk_merchant = False
        self.kyc_risk_level = 1
        self.days_since_kyc = 0
        self.total_tx_count_30d = 0
        self.tx_hour = 0
        self.day_of_week = 0
        self.time_since_last_tx_s = 0.0
        self.distance_km_from_last = 0.0
        self.louvain_community_id = 0


def test_pipeline_transform_shape():
    pipeline = FeaturePipeline()
    features = _MockFeatures()
    X = pipeline.transform(features)
    assert X.shape == (1, NUM_MODEL_FEATURES)
    assert X.dtype == np.float32


def test_pipeline_transform_with_elliptic_features():
    pipeline = FeaturePipeline()
    elliptic = {f"feature_{i}": float(i) for i in range(1, 86)}
    features = _MockFeatures(elliptic=elliptic)
    X = pipeline.transform(features)
    assert X.shape == (1, NUM_MODEL_FEATURES)
    # feature_1 should be at index 0
    assert X[0, 0] == pytest.approx(1.0)


def test_pipeline_transform_batch():
    pipeline = FeaturePipeline()
    features_list = [_MockFeatures() for _ in range(10)]
    X = pipeline.transform_batch(features_list)
    assert X.shape == (10, NUM_MODEL_FEATURES)
    assert X.dtype == np.float32


def test_pipeline_transform_batch_empty():
    pipeline = FeaturePipeline()
    X = pipeline.transform_batch([])
    assert X.shape == (0, NUM_MODEL_FEATURES)
