"""
Unit tests for the FraudMLServicer gRPC implementation.

Uses mock registry and pipeline to avoid loading real model artefacts.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np
import pytest
import grpc

from app.grpc.servicer import FraudMLServicer
from proto.gen.python.fraud.v1.fraud_pb2 import (
    PredictFraudRequest,
    BatchPredictFraudRequest,
    GetLIMEExplanationRequest,
    GetCounterfactualRequest,
    GetModelMetricsRequest,
    GetModelComparisonRequest,
    TriggerRetrainingRequest,
    TransactionFeatures,
    VerifyFaceRequest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_mock_model(fraud_prob: float = 0.85):
    model = MagicMock()
    n = 1
    proba = np.array([[1 - fraud_prob, fraud_prob]], dtype=np.float32)
    model.predict_proba.return_value = proba
    model.per_model_probabilities.return_value = {
        "lightgbm": fraud_prob,
        "random_forest": fraud_prob - 0.02,
        "xgboost": fraud_prob - 0.03,
    }
    model._models = {}
    return model


def _make_registry(fraud_prob: float = 0.85):
    registry = MagicMock()
    registry.get.return_value = _make_mock_model(fraud_prob)
    registry.available_models.return_value = ["lightgbm", "random_forest", "xgboost", "ensemble"]
    return registry


def _make_pipeline():
    pipeline = MagicMock()
    pipeline.transform.return_value = np.zeros((1, 85), dtype=np.float32)
    pipeline.transform_batch.side_effect = lambda features_list: np.zeros(
        (len(features_list), 85), dtype=np.float32
    )
    return pipeline


def _make_context():
    ctx = MagicMock(spec=grpc.ServicerContext)
    return ctx


def _make_servicer(fraud_prob: float = 0.85):
    return FraudMLServicer(
        registry=_make_registry(fraud_prob),
        feature_pipeline=_make_pipeline(),
        shap_cache={},
    )


def _make_features():
    return TransactionFeatures(
        tx_hash="abc123",
        customer_id="cust-1",
        amount=5000.0,
        velocity_1h=15000.0,
    )


# ---------------------------------------------------------------------------
# VerifyFace
# ---------------------------------------------------------------------------

def test_verify_face_returns_mock_match():
    servicer = _make_servicer()
    req = VerifyFaceRequest(selfie_s3_key="s3://selfie", document_s3_key="s3://doc", check_liveness=True)
    resp = servicer.VerifyFace(req, _make_context())
    assert resp.face_match is True
    assert resp.match_score > 0.0
    assert resp.liveness_passed is True


# ---------------------------------------------------------------------------
# PredictFraud
# ---------------------------------------------------------------------------

def test_predict_fraud_high_probability():
    servicer = _make_servicer(fraud_prob=0.92)
    req = PredictFraudRequest(features=_make_features(), model="ensemble")
    resp = servicer.PredictFraud(req, _make_context())
    assert resp.fraud_probability == pytest.approx(0.92, rel=1e-4)
    assert resp.is_fraud is True
    assert resp.risk_level == 4   # CRITICAL
    assert resp.prediction_id != ""
    assert resp.latency_ms >= 0.0


def test_predict_fraud_low_probability():
    servicer = _make_servicer(fraud_prob=0.10)
    req = PredictFraudRequest(features=_make_features())
    resp = servicer.PredictFraud(req, _make_context())
    assert resp.fraud_probability == pytest.approx(0.10, rel=1e-4)
    assert resp.is_fraud is False
    assert resp.risk_level == 1   # LOW


def test_predict_fraud_missing_features():
    servicer = _make_servicer()
    req = PredictFraudRequest(features=None, model="ensemble")
    ctx = _make_context()
    resp = servicer.PredictFraud(req, ctx)
    ctx.set_code.assert_called_with(grpc.StatusCode.INVALID_ARGUMENT)


def test_predict_fraud_model_not_found():
    servicer = _make_servicer()
    servicer._registry.get.side_effect = KeyError("gnn")
    req = PredictFraudRequest(features=_make_features(), model="gnn")
    ctx = _make_context()
    resp = servicer.PredictFraud(req, ctx)
    ctx.set_code.assert_called_with(grpc.StatusCode.NOT_FOUND)


def test_predict_fraud_caches_prediction_id():
    servicer = _make_servicer(fraud_prob=0.75)
    req = PredictFraudRequest(features=_make_features())
    resp = servicer.PredictFraud(req, _make_context())
    assert resp.prediction_id in servicer._shap_cache


# ---------------------------------------------------------------------------
# BatchPredictFraud
# ---------------------------------------------------------------------------

def test_batch_predict_returns_correct_count():
    servicer = _make_servicer(fraud_prob=0.6)
    servicer._registry.get.return_value.predict_proba.return_value = np.full(
        (5, 2), [0.4, 0.6], dtype=np.float32
    )
    req = BatchPredictFraudRequest(
        features_list=[_make_features() for _ in range(5)],
        model="ensemble",
    )
    resp = servicer.BatchPredictFraud(req, _make_context())
    assert len(resp.predictions) == 5
    assert resp.total_latency_ms >= 0.0


def test_batch_predict_exceeds_max_size():
    servicer = _make_servicer()
    from app.core.config import settings

    big_list = [_make_features()] * (settings.batch_max_size + 1)
    req = BatchPredictFraudRequest(features_list=big_list)
    ctx = _make_context()
    servicer.BatchPredictFraud(req, ctx)
    ctx.set_code.assert_called_with(grpc.StatusCode.INVALID_ARGUMENT)


# ---------------------------------------------------------------------------
# GetModelMetrics
# ---------------------------------------------------------------------------

def test_get_model_metrics_lightgbm():
    servicer = _make_servicer()
    req = GetModelMetricsRequest(model_name="lightgbm", period="test")
    resp = servicer.GetModelMetrics(req, _make_context())
    assert resp.metrics.model_name == "lightgbm"
    assert resp.metrics.auc_roc == pytest.approx(0.9649, rel=1e-3)
    assert resp.metrics.precision == pytest.approx(0.6461, rel=1e-3)


def test_get_model_metrics_random_forest():
    servicer = _make_servicer()
    req = GetModelMetricsRequest(model_name="random_forest", period="test")
    resp = servicer.GetModelMetrics(req, _make_context())
    assert resp.metrics.precision == pytest.approx(0.8834, rel=1e-3)
    assert resp.metrics.recall == pytest.approx(0.5692, rel=1e-3)


def test_get_model_metrics_ensemble_fallback():
    servicer = _make_servicer()
    req = GetModelMetricsRequest(model_name="ensemble")
    resp = servicer.GetModelMetrics(req, _make_context())
    assert resp.metrics.model_name == "ensemble"
    assert resp.metrics.auc_roc > 0.0


# ---------------------------------------------------------------------------
# GetModelComparison
# ---------------------------------------------------------------------------

def test_get_model_comparison_returns_all_models():
    servicer = _make_servicer()
    req = GetModelComparisonRequest(period="test")
    resp = servicer.GetModelComparison(req, _make_context())
    model_names = [m.model_name for m in resp.models]
    assert "lightgbm" in model_names
    assert "random_forest" in model_names
    assert "xgboost" in model_names
    assert resp.active_model == "ensemble"


# ---------------------------------------------------------------------------
# TriggerRetraining
# ---------------------------------------------------------------------------

def test_trigger_retraining_returns_queued():
    servicer = _make_servicer()
    req = TriggerRetrainingRequest(model_name="lightgbm", reason="drift_detected")
    resp = servicer.TriggerRetraining(req, _make_context())
    assert resp.status == "QUEUED"
    assert resp.job_id != ""


def test_trigger_retraining_all_models():
    servicer = _make_servicer()
    req = TriggerRetrainingRequest(model_name="", reason="scheduled")
    resp = servicer.TriggerRetraining(req, _make_context())
    assert resp.status == "QUEUED"


# ---------------------------------------------------------------------------
# HealthCheck
# ---------------------------------------------------------------------------

def test_health_check():
    servicer = _make_servicer()
    req = MagicMock()
    resp = servicer.HealthCheck(req, _make_context())
    assert resp.status == "SERVING"


# ---------------------------------------------------------------------------
# StreamPredictions
# ---------------------------------------------------------------------------

def test_stream_predictions_returns_empty_iterator():
    servicer = _make_servicer()
    req = MagicMock()
    req.min_fraud_prob = 0.7
    items = list(servicer.StreamPredictions(req, _make_context()))
    assert items == []
