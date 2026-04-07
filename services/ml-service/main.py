"""
ML Service entry point.

Runs FastAPI (REST) and gRPC simultaneously:
  - FastAPI on HTTP port   (settings.http_port,  default 8000)
  - gRPC on TCP port       (settings.grpc_port,  default 50051)

Startup sequence:
  1. Load model artefacts from artifact directory
  2. Initialise feature pipeline
  3. Build LIME explainer with a sample background dataset (if available)
  4. Start gRPC server in a background thread
  5. Start FastAPI via uvicorn (main thread)

Usage:
    python main.py
    # or
    uvicorn main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import configure_logging
from app.features.pipeline import FeaturePipeline
from app.grpc.server import build_grpc_server
from app.models.registry import ModelRegistry
from app.api.routes import router

configure_logging()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Fraud Detection ML Service",
    version=settings.service_version,
    description="Real-time fraud prediction with SHAP/LIME explainability",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
def startup_event() -> None:
    logger.info("starting %s v%s (env=%s)", settings.service_name, settings.service_version, settings.environment)

    # 1. Model registry
    registry = ModelRegistry(
        artifact_dir=settings.model_artifact_path,
        cache_ttl_s=settings.model_cache_ttl_s,
    )
    registry.load_all()
    app.state.registry = registry

    # 2. Feature pipeline
    app.state.feature_pipeline = FeaturePipeline()

    # 3. Shared prediction cache (prediction_id → (X, shap_contributions))
    app.state.shap_cache = {}

    # 4. LIME explainer — requires background training data
    app.state.lime_explainer = _build_lime_explainer(registry)

    # 5. gRPC server (background thread)
    grpc_server = build_grpc_server(
        registry=registry,
        feature_pipeline=app.state.feature_pipeline,
        shap_cache=app.state.shap_cache,
    )
    grpc_server.start()
    logger.info("gRPC server started on port %d", settings.grpc_port)

    # Daemon thread: stop gRPC when FastAPI stops
    def _grpc_wait():
        grpc_server.wait_for_termination()

    t = threading.Thread(target=_grpc_wait, daemon=True)
    t.start()
    app.state.grpc_server = grpc_server


@app.on_event("shutdown")
def shutdown_event() -> None:
    logger.info("shutting down %s", settings.service_name)
    grpc_server = getattr(app.state, "grpc_server", None)
    if grpc_server is not None:
        grpc_server.stop(grace=5)


def _build_lime_explainer(registry):
    """Build LIME explainer with a minimal synthetic background dataset.

    In production, load a sample of the actual training data from disk:
        background = np.load("ml/artifacts/background_sample.npy")
    """
    try:
        import numpy as np
        from ml.explainability.lime_explainer import LIMEFraudExplainer
        from ml.features.engineering import NUM_MODEL_FEATURES

        background_path = Path(settings.model_artifact_path) / "background_sample.npy"
        if background_path.exists():
            background = np.load(background_path)
            logger.info("LIME background data loaded: %d samples", len(background))
        else:
            # Minimal synthetic background — LIME will still work but won't be calibrated
            background = np.zeros((100, NUM_MODEL_FEATURES), dtype=np.float32)
            logger.warning("no background_sample.npy found — LIME using synthetic zeros background")

        return LIMEFraudExplainer(training_data=background)
    except Exception as exc:
        logger.warning("could not initialise LIME explainer: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.http_port,
        log_level=settings.log_level.lower(),
        reload=settings.environment == "development",
    )
