"""
ML Service configuration — loaded from environment variables.
All settings have sensible defaults for local development.
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Service ---
    service_name: str         = "ml-service"
    service_version: str      = "1.0.0"
    environment: str          = "development"
    log_level: str            = "info"
    http_port: int            = 8000
    grpc_port: int            = 50051

    # --- ML / Models ---
    model_artifact_path: str  = "./ml/artifacts"
    model_fraud_threshold: float = Field(0.7, ge=0.0, le=1.0)
    model_ab_ratio: float     = Field(0.0, ge=0.0, le=1.0,
                                       description="Fraction of traffic to route to challenger model")
    active_model: str         = "ensemble"  # ensemble, xgboost, lightgbm, random_forest, gnn

    # --- MLflow ---
    mlflow_tracking_uri: str  = "http://localhost:5000"
    mlflow_experiment_name: str = "fraud-detection"

    # --- IAM gRPC (for token validation) ---
    iam_service_host: str     = "localhost"
    iam_service_grpc_port: int = 50060
    iam_tls_enabled: bool     = False

    # --- Observability ---
    jaeger_endpoint: str      = "http://localhost:14268/api/traces"
    otel_sample_rate: float   = Field(1.0, ge=0.0, le=1.0)

    # --- Feature pipeline ---
    feature_pipeline_version: str = "v1.0"
    shap_num_features: int    = 5   # top-N SHAP features to return per prediction

    # --- Performance ---
    prediction_timeout_s: float = 2.0   # abort prediction if > 2s
    batch_max_size: int       = 1000    # max transactions per BatchPredict call
    model_cache_ttl_s: int    = 300     # model reload check interval


# Singleton instance — import this everywhere
settings = Settings()
