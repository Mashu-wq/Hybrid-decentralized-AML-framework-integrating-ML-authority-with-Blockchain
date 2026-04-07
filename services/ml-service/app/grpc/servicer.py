"""
FraudMLService gRPC servicer implementation.

Maps proto requests → feature pipeline → model registry → proto responses.

All RPCs:
  VerifyFace             — delegate to mock face-match (real impl in KYC service)
  PredictFraud           — single prediction with SHAP
  BatchPredictFraud      — batch prediction
  StreamPredictions      — server-side streaming (in-process queue)
  GetLIMEExplanation     — LIME from prediction cache
  GetCounterfactual      — counterfactual from prediction cache
  GetModelMetrics        — Colab benchmark metrics
  GetModelComparison     — all models side-by-side
  PredictWithModel       — route to specific model (A/B)
  TriggerRetraining      — async MLflow run (stub)
  HealthCheck            — liveness
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from typing import Any

import grpc
import numpy as np

from app.core.config import settings

logger = logging.getLogger(__name__)

# Risk level enum mapping (matches proto common.proto RiskLevel)
_RISK_LEVEL_MAP = {
    "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


def _risk_level_enum(prob: float) -> int:
    if prob >= 0.85:
        return _RISK_LEVEL_MAP["CRITICAL"]
    if prob >= 0.70:
        return _RISK_LEVEL_MAP["HIGH"]
    if prob >= 0.50:
        return _RISK_LEVEL_MAP["MEDIUM"]
    return _RISK_LEVEL_MAP["LOW"]


class FraudMLServicer:
    """Concrete implementation of FraudMLServiceServicer."""

    def __init__(self, registry, feature_pipeline, shap_cache: dict) -> None:
        self._registry    = registry
        self._pipeline    = feature_pipeline
        self._shap_cache  = shap_cache

    # ------------------------------------------------------------------
    # Face verification (stub — real ML lives in KYC service)
    # ------------------------------------------------------------------

    def VerifyFace(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import VerifyFaceResponse
        except ImportError:
            from fraud_pb2 import VerifyFaceResponse  # type: ignore

        # Mock: always pass (replace with real DeepFace / FaceNet inference)
        return VerifyFaceResponse(
            face_match=True,
            match_score=0.92,
            liveness_passed=True,
            liveness_score=0.98,
            model_version="mock-v1",
        )

    # ------------------------------------------------------------------
    # Primary prediction
    # ------------------------------------------------------------------

    def PredictFraud(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                PredictFraudResponse,
                SHAPContribution,
            )
        except ImportError:
            from fraud_pb2 import PredictFraudResponse, SHAPContribution  # type: ignore

        if request.features is None:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("features field is required")
            return PredictFraudResponse()

        model_name = request.model or settings.active_model
        try:
            model = self._registry.get(model_name)
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"model '{model_name}' not loaded")
            return PredictFraudResponse()

        X = self._pipeline.transform(request.features)
        t0 = time.perf_counter()
        proba = model.predict_proba(X)
        latency_ms = (time.perf_counter() - t0) * 1000

        fraud_prob = float(proba[0, 1])
        is_fraud   = fraud_prob >= settings.model_fraud_threshold

        # Per-model breakdown
        model_probabilities = {}
        if hasattr(model, "per_model_probabilities"):
            model_probabilities = model.per_model_probabilities(X)

        # SHAP top-N
        shap_values = []
        base_value  = 0.0
        try:
            from ml.explainability.shap_explainer import TreeSHAPExplainer
            base_model = _best_tree_model(model, self._registry)
            if base_model is not None:
                explainer = TreeSHAPExplainer(base_model._estimator)
                top = explainer.top_contributions(X, top_n=settings.shap_num_features)
                for c in top[0]:
                    shap_values.append(SHAPContribution(
                        feature_name=c.feature_name,
                        shap_value=c.shap_value,
                        feature_value=c.feature_value,
                    ))
                base_value = explainer.explain(X)[0].base_value
        except Exception as exc:
            logger.debug("SHAP computation failed (non-fatal): %s", exc)

        prediction_id = str(uuid.uuid4())
        self._shap_cache[prediction_id] = (X.copy(), shap_values)
        _trim_cache(self._shap_cache)

        return PredictFraudResponse(
            fraud_probability=fraud_prob,
            is_fraud=is_fraud,
            risk_level=_risk_level_enum(fraud_prob),
            model_probabilities=model_probabilities,
            shap_values=shap_values,
            base_value=base_value,
            model_version=settings.service_version,
            prediction_id=prediction_id,
            latency_ms=round(latency_ms, 3),
        )

    # ------------------------------------------------------------------
    # Batch prediction
    # ------------------------------------------------------------------

    def BatchPredictFraud(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                BatchPredictFraudResponse,
                PredictFraudResponse,
            )
        except ImportError:
            from fraud_pb2 import BatchPredictFraudResponse, PredictFraudResponse  # type: ignore

        features_list = list(request.features_list)
        if len(features_list) > settings.batch_max_size:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"batch size {len(features_list)} exceeds max {settings.batch_max_size}"
            )
            return BatchPredictFraudResponse()

        model_name = request.model or settings.active_model
        try:
            model = self._registry.get(model_name)
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"model '{model_name}' not loaded")
            return BatchPredictFraudResponse()

        X_batch = self._pipeline.transform_batch(features_list)
        t0      = time.perf_counter()
        probas  = model.predict_proba(X_batch)
        total_ms = (time.perf_counter() - t0) * 1000

        predictions = []
        per_sample_ms = total_ms / max(len(features_list), 1)
        for proba_row in probas:
            fraud_prob = float(proba_row[1])
            predictions.append(PredictFraudResponse(
                fraud_probability=fraud_prob,
                is_fraud=fraud_prob >= settings.model_fraud_threshold,
                risk_level=_risk_level_enum(fraud_prob),
                model_version=settings.service_version,
                prediction_id=str(uuid.uuid4()),
                latency_ms=round(per_sample_ms, 3),
            ))

        return BatchPredictFraudResponse(
            predictions=predictions,
            total_latency_ms=round(total_ms, 3),
        )

    # ------------------------------------------------------------------
    # Server-side streaming
    # ------------------------------------------------------------------

    def StreamPredictions(self, request, context):
        """Stream predictions above min_fraud_prob threshold (demo: yields 0 items).

        In production: subscribe to the tx.events Kafka topic and yield
        PredictFraudResponse for each transaction processed in real-time.
        """
        logger.info(
            "StreamPredictions: min_fraud_prob=%.2f (streaming not yet connected to Kafka)",
            request.min_fraud_prob,
        )
        # Yield nothing — client receives end-of-stream immediately
        return iter([])

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------

    def GetLIMEExplanation(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                GetLIMEExplanationResponse,
                LIMEFeatureWeight,
            )
        except ImportError:
            from fraud_pb2 import GetLIMEExplanationResponse, LIMEFeatureWeight  # type: ignore

        if request.prediction_id not in self._shap_cache:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"prediction_id '{request.prediction_id}' not in cache")
            return GetLIMEExplanationResponse()

        X, _ = self._shap_cache[request.prediction_id]
        model_name = settings.active_model
        try:
            model = self._registry.get(model_name)
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"model '{model_name}' not loaded")
            return GetLIMEExplanationResponse()

        try:
            from ml.explainability.lime_explainer import LIMEFraudExplainer
            # Use X itself as a minimal background (real impl would use training data)
            explainer = LIMEFraudExplainer(
                training_data=X,
                num_features=request.num_features or 10,
            )
            result = explainer.explain_instance(
                instance=X[0],
                predict_fn=model.predict_proba,
                prediction_id=request.prediction_id,
            )
            return GetLIMEExplanationResponse(
                prediction_id=result.prediction_id,
                feature_weights=[
                    LIMEFeatureWeight(
                        feature_name=fw.feature_name,
                        weight=fw.weight,
                        condition=fw.condition,
                    )
                    for fw in result.feature_weights
                ],
                local_accuracy=result.local_accuracy,
                intercept=result.intercept,
            )
        except Exception as exc:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"LIME failed: {exc}")
            return GetLIMEExplanationResponse()

    def GetCounterfactual(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                CounterfactualChange,
                GetCounterfactualResponse,
            )
        except ImportError:
            from fraud_pb2 import CounterfactualChange, GetCounterfactualResponse  # type: ignore

        if request.prediction_id not in self._shap_cache:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"prediction_id '{request.prediction_id}' not in cache")
            return GetCounterfactualResponse()

        X, shap_contributions = self._shap_cache[request.prediction_id]
        model_name = settings.active_model
        try:
            model = self._registry.get(model_name)
        except KeyError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"model '{model_name}' not loaded")
            return GetCounterfactualResponse()

        from ml.explainability.counterfactual import CounterfactualExplainer
        from ml.features.engineering import SELECTED_FEATURE_NAMES

        shap_importances = None
        if shap_contributions:
            name_to_idx = {n: i for i, n in enumerate(SELECTED_FEATURE_NAMES)}
            shap_importances = np.zeros(len(SELECTED_FEATURE_NAMES), dtype=np.float32)
            for c in shap_contributions:
                idx = name_to_idx.get(c.feature_name)
                if idx is not None:
                    shap_importances[idx] = abs(c.shap_value)

        cf_explainer = CounterfactualExplainer(predict_fn=model.predict_proba)
        result = cf_explainer.explain(
            instance=X[0],
            target_prob=request.target_prob or 0.3,
            prediction_id=request.prediction_id,
            shap_importances=shap_importances,
        )

        return GetCounterfactualResponse(
            prediction_id=result.prediction_id,
            changes=[
                CounterfactualChange(
                    feature_name=c.feature_name,
                    current_value=c.current_value,
                    suggested_value=c.suggested_value,
                    delta=c.delta,
                )
                for c in result.changes
            ],
            resulting_prob=result.resulting_prob,
            achievable=result.achievable,
        )

    # ------------------------------------------------------------------
    # Model metrics & comparison
    # ------------------------------------------------------------------

    def GetModelMetrics(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                GetModelMetricsResponse,
                ModelMetrics,
            )
        except ImportError:
            from fraud_pb2 import GetModelMetricsResponse, ModelMetrics  # type: ignore

        from ml.evaluation.evaluator import COLAB_BENCHMARK

        target = request.model_name or settings.active_model
        for m in COLAB_BENCHMARK.models:
            if m.model_name == target:
                return GetModelMetricsResponse(
                    metrics=ModelMetrics(
                        model_name=m.model_name, model_version=m.model_version,
                        precision=m.precision, recall=m.recall, f1_score=m.f1_score,
                        auc_roc=m.auc_roc, auc_pr=m.auc_pr, accuracy=m.accuracy,
                        true_positives=m.true_positives, false_positives=m.false_positives,
                        true_negatives=m.true_negatives, false_negatives=m.false_negatives,
                        sample_count=m.sample_count, period=request.period or "test",
                    )
                )

        # Ensemble: return weighted average
        models = COLAB_BENCHMARK.models
        return GetModelMetricsResponse(
            metrics=ModelMetrics(
                model_name="ensemble", model_version="colab-v1",
                precision=sum(m.precision for m in models) / len(models),
                recall=sum(m.recall for m in models) / len(models),
                f1_score=sum(m.f1_score for m in models) / len(models),
                auc_roc=max(m.auc_roc for m in models),
                auc_pr=0.0, accuracy=0.0,
                true_positives=0, false_positives=0, true_negatives=0, false_negatives=0,
                sample_count=9642, period=request.period or "test",
            )
        )

    def GetModelComparison(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import (
                GetModelComparisonResponse,
                ModelMetrics,
            )
        except ImportError:
            from fraud_pb2 import GetModelComparisonResponse, ModelMetrics  # type: ignore

        from ml.evaluation.evaluator import COLAB_BENCHMARK

        return GetModelComparisonResponse(
            models=[
                ModelMetrics(
                    model_name=m.model_name, model_version=m.model_version,
                    precision=m.precision, recall=m.recall, f1_score=m.f1_score,
                    auc_roc=m.auc_roc, auc_pr=m.auc_pr, accuracy=m.accuracy,
                    true_positives=m.true_positives, false_positives=m.false_positives,
                    true_negatives=m.true_negatives, false_negatives=m.false_negatives,
                    sample_count=m.sample_count, period=request.period or "test",
                )
                for m in COLAB_BENCHMARK.models
            ],
            active_model=COLAB_BENCHMARK.active_model,
        )

    # ------------------------------------------------------------------
    # A/B Test
    # ------------------------------------------------------------------

    def PredictWithModel(self, request, context):
        """Route to a specific model version."""
        model_request_copy = type("_R", (), {
            "features": request.features,
            "model": request.model_name or settings.active_model,
        })()
        return self.PredictFraud(model_request_copy, context)

    # ------------------------------------------------------------------
    # Retraining (async stub)
    # ------------------------------------------------------------------

    def TriggerRetraining(self, request, context):
        try:
            from proto.gen.python.fraud.v1.fraud_pb2 import TriggerRetrainingResponse
        except ImportError:
            from fraud_pb2 import TriggerRetrainingResponse  # type: ignore

        job_id = str(uuid.uuid4())
        logger.info(
            "TriggerRetraining: model=%s reason=%s job_id=%s",
            request.model_name, request.reason, job_id,
        )
        # In production: submit an MLflow run via mlflow.projects.run()
        return TriggerRetrainingResponse(
            job_id=job_id,
            status="QUEUED",
            message=f"Retraining queued for model '{request.model_name or 'all'}'",
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def HealthCheck(self, request, context):
        try:
            from proto.gen.python.common.v1.common_pb2 import HealthCheckResponse
        except ImportError:
            # Minimal stub
            class HealthCheckResponse:  # type: ignore[no-redef]
                def __init__(self, status="SERVING"): self.status = status
        return HealthCheckResponse(status="SERVING")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _best_tree_model(model, registry):
    if hasattr(model, "_models"):
        for name in ("lightgbm", "xgboost", "random_forest"):
            base = model._models.get(name)
            if base is not None and getattr(base, "_estimator", None) is not None:
                return base
    try:
        return registry.get("lightgbm")
    except KeyError:
        return None


def _trim_cache(cache: dict, max_size: int = 10_000) -> None:
    while len(cache) > max_size:
        del cache[next(iter(cache))]
