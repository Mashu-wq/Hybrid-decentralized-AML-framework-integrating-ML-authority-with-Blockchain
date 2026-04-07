"""
FastAPI REST routes for the ML service.

Endpoints:
  POST /predict                  — single transaction fraud prediction
  POST /predict/batch            — batch prediction (up to 1000 transactions)
  POST /explain/lime             — LIME explanation for a stored prediction
  POST /explain/counterfactual   — counterfactual for a stored prediction
  GET  /model/metrics            — performance metrics for a specific model
  GET  /model/comparison         — side-by-side comparison of all models
  GET  /health                   — liveness + loaded models
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Optional

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.config import settings
from app.schemas.prediction import (
    BatchPredictRequest,
    CounterfactualRequest,
    CounterfactualResponse,
    HealthResponse,
    LIMERequest,
    LIMEResponse,
    ModelComparisonResponse,
    ModelMetricsRequest,
    ModelMetricsResponse,
    ModelMetricsSchema,
    PredictRequest,
    PredictResponse,
    SHAPContributionSchema,
    CounterfactualChangeSchema,
    LIMEFeatureWeightSchema,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Dependency helpers — injected via app.state (set in main.py)
# ---------------------------------------------------------------------------

def get_registry(request: Request):
    return request.app.state.registry

def get_pipeline(request: Request):
    return request.app.state.feature_pipeline

def get_shap_cache(request: Request) -> dict:
    return request.app.state.shap_cache  # dict[prediction_id → (X_row, shap_contributions)]

def get_lime_explainer(request: Request):
    return request.app.state.lime_explainer  # may be None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse)
def health(registry=Depends(get_registry)):
    return HealthResponse(
        status="serving",
        loaded_models=registry.available_models(),
        active_model=settings.active_model,
        model_version=settings.service_version,
    )


# ---------------------------------------------------------------------------
# Predict
# ---------------------------------------------------------------------------

@router.post("/predict", response_model=PredictResponse)
def predict(
    req: PredictRequest,
    request: Request,
    registry=Depends(get_registry),
    pipeline=Depends(get_pipeline),
    shap_cache: dict = Depends(get_shap_cache),
):
    model_name = req.model or settings.active_model
    try:
        model = registry.get(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"model '{model_name}' not loaded")

    X = pipeline.transform(req.features)
    t0 = time.perf_counter()
    proba = model.predict_proba(X)
    latency_ms = (time.perf_counter() - t0) * 1000

    fraud_prob = float(proba[0, 1])
    is_fraud   = fraud_prob >= settings.model_fraud_threshold
    risk_level = _risk_level(fraud_prob)

    # Per-model breakdown (for ensemble)
    model_probabilities: dict[str, float] = {}
    if model_name == "ensemble" and hasattr(model, "per_model_probabilities"):
        model_probabilities = model.per_model_probabilities(X)

    # SHAP top-N
    shap_contributions = []
    base_value = 0.0
    try:
        from ml.explainability.shap_explainer import TreeSHAPExplainer
        base_model = _get_base_model_for_shap(model, registry)
        if base_model is not None:
            explainer = TreeSHAPExplainer(base_model._estimator)
            top = explainer.top_contributions(X, top_n=settings.shap_num_features)
            for c in top[0]:
                shap_contributions.append(SHAPContributionSchema(
                    feature_name=c.feature_name,
                    shap_value=c.shap_value,
                    feature_value=c.feature_value,
                ))
            results = explainer.explain(X)
            base_value = results[0].base_value if results else 0.0
    except Exception:
        pass  # SHAP is best-effort; don't fail predictions over it

    prediction_id = str(uuid.uuid4())

    # Cache for LIME / counterfactual lookup
    shap_cache[prediction_id] = (X.copy(), req.features, shap_contributions)
    # Limit cache size
    if len(shap_cache) > 10_000:
        oldest = next(iter(shap_cache))
        del shap_cache[oldest]

    return PredictResponse(
        fraud_probability=fraud_prob,
        is_fraud=is_fraud,
        risk_level=risk_level,
        model_probabilities=model_probabilities,
        shap_values=shap_contributions,
        base_value=base_value,
        model_version=settings.service_version,
        prediction_id=prediction_id,
        latency_ms=round(latency_ms, 3),
        predicted_at=datetime.utcnow(),
    )


@router.post("/predict/batch", response_model=list[PredictResponse])
def batch_predict(
    req: BatchPredictRequest,
    request: Request,
    registry=Depends(get_registry),
    pipeline=Depends(get_pipeline),
    shap_cache: dict = Depends(get_shap_cache),
):
    if len(req.features_list) > settings.batch_max_size:
        raise HTTPException(
            status_code=400,
            detail=f"batch size {len(req.features_list)} exceeds max {settings.batch_max_size}",
        )

    model_name = req.model or settings.active_model
    try:
        model = registry.get(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"model '{model_name}' not loaded")

    X_batch = pipeline.transform_batch(req.features_list)
    t0      = time.perf_counter()
    probas  = model.predict_proba(X_batch)
    total_ms = (time.perf_counter() - t0) * 1000

    responses = []
    for i, (features, proba_row) in enumerate(zip(req.features_list, probas)):
        fraud_prob = float(proba_row[1])
        is_fraud   = fraud_prob >= settings.model_fraud_threshold
        prediction_id = str(uuid.uuid4())
        shap_cache[prediction_id] = (X_batch[i:i+1].copy(), features, [])
        responses.append(PredictResponse(
            fraud_probability=fraud_prob,
            is_fraud=is_fraud,
            risk_level=_risk_level(fraud_prob),
            model_version=settings.service_version,
            prediction_id=prediction_id,
            latency_ms=round(total_ms / len(req.features_list), 3),
            predicted_at=datetime.utcnow(),
        ))

    return responses


# ---------------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------------

@router.post("/explain/lime", response_model=LIMEResponse)
def explain_lime(
    req: LIMERequest,
    request: Request,
    registry=Depends(get_registry),
    shap_cache: dict = Depends(get_shap_cache),
    lime_explainer=Depends(get_lime_explainer),
):
    if req.prediction_id not in shap_cache:
        raise HTTPException(status_code=404, detail=f"prediction_id '{req.prediction_id}' not found in cache")

    if lime_explainer is None:
        raise HTTPException(status_code=503, detail="LIME explainer not initialised (no training data loaded)")

    X, _, _ = shap_cache[req.prediction_id]
    model_name = settings.active_model
    try:
        model = registry.get(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"model '{model_name}' not loaded")

    result = lime_explainer.explain_instance(
        instance=X[0],
        predict_fn=model.predict_proba,
        prediction_id=req.prediction_id,
        num_features=req.num_features,
    )

    return LIMEResponse(
        prediction_id=result.prediction_id,
        feature_weights=[
            LIMEFeatureWeightSchema(
                feature_name=fw.feature_name,
                weight=fw.weight,
                condition=fw.condition,
            )
            for fw in result.feature_weights
        ],
        local_accuracy=result.local_accuracy,
        intercept=result.intercept,
    )


@router.post("/explain/counterfactual", response_model=CounterfactualResponse)
def explain_counterfactual(
    req: CounterfactualRequest,
    request: Request,
    registry=Depends(get_registry),
    shap_cache: dict = Depends(get_shap_cache),
):
    if req.prediction_id not in shap_cache:
        raise HTTPException(status_code=404, detail=f"prediction_id '{req.prediction_id}' not found in cache")

    X, _, shap_contributions = shap_cache[req.prediction_id]
    model_name = settings.active_model
    try:
        model = registry.get(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"model '{model_name}' not loaded")

    from ml.explainability.counterfactual import CounterfactualExplainer
    from ml.features.engineering import SELECTED_FEATURE_NAMES

    shap_importances = None
    if shap_contributions:
        # Build importance array from cached SHAP contributions
        name_to_idx = {n: i for i, n in enumerate(SELECTED_FEATURE_NAMES)}
        shap_importances = np.zeros(len(SELECTED_FEATURE_NAMES), dtype=np.float32)
        for c in shap_contributions:
            idx = name_to_idx.get(c.feature_name)
            if idx is not None:
                shap_importances[idx] = abs(c.shap_value)

    cf_explainer = CounterfactualExplainer(
        predict_fn=model.predict_proba,
        feature_names=SELECTED_FEATURE_NAMES,
    )
    result = cf_explainer.explain(
        instance=X[0],
        target_prob=req.target_prob,
        prediction_id=req.prediction_id,
        shap_importances=shap_importances,
    )

    return CounterfactualResponse(
        prediction_id=result.prediction_id,
        changes=[
            CounterfactualChangeSchema(
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


# ---------------------------------------------------------------------------
# Model metrics & comparison
# ---------------------------------------------------------------------------

@router.get("/model/metrics", response_model=ModelMetricsResponse)
def model_metrics(model_name: str = "", period: str = "test"):
    from ml.evaluation.evaluator import COLAB_BENCHMARK

    target = model_name or settings.active_model
    for m in COLAB_BENCHMARK.models:
        if m.model_name == target or target == "ensemble":
            return ModelMetricsResponse(
                metrics=ModelMetricsSchema(
                    model_name=m.model_name,
                    model_version=m.model_version,
                    precision=m.precision, recall=m.recall, f1_score=m.f1_score,
                    accuracy=m.accuracy, auc_roc=m.auc_roc, auc_pr=m.auc_pr,
                    true_positives=m.true_positives, false_positives=m.false_positives,
                    true_negatives=m.true_negatives, false_negatives=m.false_negatives,
                    sample_count=m.sample_count,
                    avg_latency_ms=m.avg_latency_ms, p95_latency_ms=m.p95_latency_ms,
                    period=period,
                )
            )
    raise HTTPException(status_code=404, detail=f"no metrics for model '{target}'")


@router.get("/model/comparison", response_model=ModelComparisonResponse)
def model_comparison():
    from ml.evaluation.evaluator import COLAB_BENCHMARK

    return ModelComparisonResponse(
        models=[
            ModelMetricsSchema(
                model_name=m.model_name, model_version=m.model_version,
                precision=m.precision, recall=m.recall, f1_score=m.f1_score,
                accuracy=m.accuracy, auc_roc=m.auc_roc, auc_pr=m.auc_pr,
                true_positives=m.true_positives, false_positives=m.false_positives,
                true_negatives=m.true_negatives, false_negatives=m.false_negatives,
                sample_count=m.sample_count,
                avg_latency_ms=m.avg_latency_ms, p95_latency_ms=m.p95_latency_ms,
                period="test",
            )
            for m in COLAB_BENCHMARK.models
        ],
        active_model=COLAB_BENCHMARK.active_model,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_level(prob: float) -> str:
    if prob >= 0.85:
        return "CRITICAL"
    if prob >= 0.70:
        return "HIGH"
    if prob >= 0.50:
        return "MEDIUM"
    return "LOW"


def _get_base_model_for_shap(model, registry):
    """Return the best available tree model for SHAP computation."""
    if hasattr(model, "_models"):  # EnsembleModel
        for name in ("lightgbm", "xgboost", "random_forest"):
            base = model._models.get(name)
            if base is not None and base._estimator is not None:
                return base
    # Fallback: try to get lightgbm directly
    try:
        return registry.get("lightgbm")
    except KeyError:
        return None
