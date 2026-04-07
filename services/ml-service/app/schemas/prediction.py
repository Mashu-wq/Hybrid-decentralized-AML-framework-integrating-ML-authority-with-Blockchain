"""
Pydantic v2 schemas for the ML service REST API.

These mirror the proto message structure so the FastAPI layer can
validate inputs and serialize outputs without depending on protobuf.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class TransactionFeaturesSchema(BaseModel):
    """REST representation of TransactionFeatures proto."""
    tx_hash:      str  = ""
    customer_id:  str  = ""

    # Temporal
    tx_hour:              int    = 0
    day_of_week:          int    = 0
    is_weekend:           bool   = False
    time_since_last_tx_s: float  = 0.0
    tx_frequency_1h:      float  = 0.0
    tx_frequency_24h:     float  = 0.0

    # Amount / behavioral
    amount:               float  = 0.0
    currency_code:        str    = "USD"
    amount_usd_equiv:     float  = 0.0
    avg_amount_7d:        float  = 0.0
    avg_amount_30d:       float  = 0.0
    std_amount_30d:       float  = 0.0
    amount_deviation_score: float = 0.0
    velocity_1h:          float  = 0.0
    velocity_24h:         float  = 0.0

    # Geographic
    country_code:         str    = ""
    geographic_risk_score: float = 0.0
    cross_border_flag:    bool   = False
    country_change_2h:    bool   = False
    distance_km_from_last: float = 0.0

    # Merchant
    merchant_category:    str    = ""
    merchant_risk_score:  float  = 0.0
    is_high_risk_merchant: bool  = False

    # KYC / customer
    customer_risk_score:  float  = 0.0
    kyc_risk_level:       int    = 1
    days_since_kyc:       int    = 0
    total_tx_count_30d:   int    = 0

    # Graph features
    pagerank:             float  = 0.0
    clustering_coefficient: float = 0.0
    betweenness_centrality: float = 0.0
    louvain_community_id: int    = 0
    hops_to_known_fraudster: int = -1
    direct_fraud_neighbors: int  = 0

    # Elliptic raw features (key: "feature_1" … "feature_165")
    elliptic_features: dict[str, float] = Field(default_factory=dict)


class PredictRequest(BaseModel):
    features: TransactionFeaturesSchema
    model:    str = ""   # "" → use active_model from settings


class BatchPredictRequest(BaseModel):
    features_list: list[TransactionFeaturesSchema]
    model:         str = ""


class LIMERequest(BaseModel):
    prediction_id: str
    num_features:  int = 10


class CounterfactualRequest(BaseModel):
    prediction_id: str
    target_prob:   float = Field(0.3, ge=0.0, le=1.0)


class ModelMetricsRequest(BaseModel):
    model_name: str = ""    # "" → active ensemble
    period:     str = "test"


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class SHAPContributionSchema(BaseModel):
    feature_name:  str
    shap_value:    float
    feature_value: float


class PredictResponse(BaseModel):
    fraud_probability:   float
    is_fraud:            bool
    risk_level:          str     # LOW / MEDIUM / HIGH / CRITICAL
    model_probabilities: dict[str, float] = Field(default_factory=dict)
    shap_values:         list[SHAPContributionSchema] = Field(default_factory=list)
    base_value:          float = 0.0
    model_version:       str   = ""
    prediction_id:       str   = ""
    latency_ms:          float = 0.0
    predicted_at:        datetime = Field(default_factory=datetime.utcnow)


class LIMEFeatureWeightSchema(BaseModel):
    feature_name: str
    weight:       float
    condition:    str


class LIMEResponse(BaseModel):
    prediction_id:   str
    feature_weights: list[LIMEFeatureWeightSchema]
    local_accuracy:  float
    intercept:       float


class CounterfactualChangeSchema(BaseModel):
    feature_name:    str
    current_value:   float
    suggested_value: float
    delta:           float


class CounterfactualResponse(BaseModel):
    prediction_id:  str
    changes:        list[CounterfactualChangeSchema]
    resulting_prob: float
    achievable:     bool


class ModelMetricsSchema(BaseModel):
    model_name:      str
    model_version:   str
    precision:       float
    recall:          float
    f1_score:        float
    accuracy:        float
    auc_roc:         float
    auc_pr:          float
    true_positives:  int
    false_positives: int
    true_negatives:  int
    false_negatives: int
    sample_count:    int
    avg_latency_ms:  float
    p95_latency_ms:  float
    period:          str


class ModelMetricsResponse(BaseModel):
    metrics: ModelMetricsSchema


class ModelComparisonResponse(BaseModel):
    models:       list[ModelMetricsSchema]
    active_model: str


class HealthResponse(BaseModel):
    status:           str
    loaded_models:    list[str]
    active_model:     str
    model_version:    str = "1.0.0"
