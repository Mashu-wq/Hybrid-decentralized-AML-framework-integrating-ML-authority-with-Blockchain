"""
gRPC server setup for the ML service.

Applies all four interceptors (logging, tracing, recovery, auth) and
registers the FraudMLServicer.
"""
from __future__ import annotations

import logging
from concurrent import futures

import grpc

from app.core.config import settings
from app.grpc.interceptors import (
    ServerAuthInterceptor,
    ServerLoggingInterceptor,
    ServerRecoveryInterceptor,
    ServerTracingInterceptor,
)
from app.grpc.servicer import FraudMLServicer

logger = logging.getLogger(__name__)


def build_grpc_server(
    registry,
    feature_pipeline,
    shap_cache: dict,
    max_workers: int = 10,
) -> grpc.Server:
    """Build and configure the gRPC server.

    Args:
        registry:         Loaded ModelRegistry instance.
        feature_pipeline: FeaturePipeline instance.
        shap_cache:       Shared prediction cache dict.
        max_workers:      Thread pool size.

    Returns:
        Configured (but not started) grpc.Server.
    """
    interceptors = [
        ServerRecoveryInterceptor(),
        ServerLoggingInterceptor(),
        ServerTracingInterceptor(),
        ServerAuthInterceptor(
            iam_host=settings.iam_service_host,
            iam_port=settings.iam_service_grpc_port,
        ),
    ]

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        interceptors=interceptors,
        options=[
            ("grpc.max_send_message_length",    50 * 1024 * 1024),  # 50 MB
            ("grpc.max_receive_message_length",  50 * 1024 * 1024),
            ("grpc.keepalive_time_ms",           30_000),
            ("grpc.keepalive_timeout_ms",        10_000),
            ("grpc.keepalive_permit_without_calls", True),
        ],
    )

    servicer = FraudMLServicer(
        registry=registry,
        feature_pipeline=feature_pipeline,
        shap_cache=shap_cache,
    )

    try:
        from proto.gen.python.fraud.v1.fraud_pb2_grpc import (
            add_FraudMLServiceServicer_to_server,
        )
    except ImportError:
        from fraud_pb2_grpc import add_FraudMLServiceServicer_to_server  # type: ignore

    add_FraudMLServiceServicer_to_server(servicer, server)

    port = f"[::]:{settings.grpc_port}"
    server.add_insecure_port(port)
    logger.info("gRPC server configured on port %d", settings.grpc_port)

    return server
