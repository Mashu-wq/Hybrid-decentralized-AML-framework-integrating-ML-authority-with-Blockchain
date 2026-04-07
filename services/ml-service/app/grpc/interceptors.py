"""
gRPC interceptors for the ML service (Python).

Mirrors the Go middleware package — provides:
  - ServerLoggingInterceptor   : structured JSON log per RPC call
  - ServerTracingInterceptor   : OpenTelemetry span per call
  - ServerAuthInterceptor      : JWT validation via IAM service gRPC
  - ServerRecoveryInterceptor  : catch exceptions → INTERNAL status

Usage (in main.py):
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=20),
        interceptors=[
            ServerRecoveryInterceptor(),
            ServerLoggingInterceptor(logger),
            ServerTracingInterceptor("ml-service"),
            ServerAuthInterceptor(iam_stub, public_methods),
        ],
    )
"""
from __future__ import annotations

import time
import traceback
import uuid
from collections.abc import Callable
from typing import Any

import grpc
import structlog
from opentelemetry import trace
from opentelemetry.trace import StatusCode

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Metadata key constants (must match Go middleware package)
# ---------------------------------------------------------------------------

META_REQUEST_ID = "x-request-id"
META_TRACE_ID   = "x-trace-id"
META_SPAN_ID    = "x-span-id"
META_USER_ID    = "x-user-id"
META_USER_ROLE  = "x-user-role"
META_CALLER_SVC = "x-caller-service"
META_AUTH_TOKEN = "authorization"


# ---------------------------------------------------------------------------
# Helper: extract metadata value from gRPC ServicerContext
# ---------------------------------------------------------------------------

def _get_meta(context: grpc.ServicerContext, key: str, default: str = "") -> str:
    """Extract a single value from incoming gRPC metadata."""
    for k, v in context.invocation_metadata():
        if k.lower() == key.lower():
            return v
    return default


def _extract_bearer_token(context: grpc.ServicerContext) -> str | None:
    """Extract token from 'authorization: Bearer <token>' metadata."""
    raw = _get_meta(context, META_AUTH_TOKEN)
    if not raw:
        return None
    if raw.lower().startswith("bearer "):
        return raw[7:]
    return raw


# ---------------------------------------------------------------------------
# Base interceptor — grpc.ServerInterceptor interface
# ---------------------------------------------------------------------------

class _BaseInterceptor(grpc.ServerInterceptor):
    """Base class providing a helper to extract handler info."""

    @staticmethod
    def _method_name(handler_call_details: grpc.HandlerCallDetails) -> str:
        return handler_call_details.method or "unknown"


# ---------------------------------------------------------------------------
# Recovery interceptor — converts exceptions to gRPC INTERNAL status
# ---------------------------------------------------------------------------

class ServerRecoveryInterceptor(_BaseInterceptor):
    """Catches any unhandled exception in an RPC handler and returns
    INTERNAL status instead of crashing the server process."""

    def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        method = self._method_name(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        def wrap_unary(func: Callable) -> Callable:
            def wrapper(request: Any, context: grpc.ServicerContext) -> Any:
                try:
                    return func(request, context)
                except Exception as exc:  # noqa: BLE001
                    request_id = _get_meta(context, META_REQUEST_ID, "unknown")
                    logger.error(
                        "grpc_handler_panic",
                        method=method,
                        request_id=request_id,
                        error=str(exc),
                        traceback=traceback.format_exc(),
                    )
                    context.set_code(grpc.StatusCode.INTERNAL)
                    context.set_details(
                        f"Internal server error — request_id: {request_id}"
                    )
                    return None
            return wrapper

        if handler.unary_unary:
            return handler._replace(unary_unary=wrap_unary(handler.unary_unary))
        if handler.unary_stream:
            return handler._replace(unary_stream=wrap_unary(handler.unary_stream))
        return handler


# ---------------------------------------------------------------------------
# Logging interceptor
# ---------------------------------------------------------------------------

class ServerLoggingInterceptor(_BaseInterceptor):
    """Structured JSON log for every incoming RPC with latency and status."""

    def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        method = self._method_name(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        def wrap(func: Callable) -> Callable:
            def wrapper(request: Any, context: grpc.ServicerContext) -> Any:
                request_id = _get_meta(context, META_REQUEST_ID) or str(uuid.uuid4())
                trace_id   = _get_meta(context, META_TRACE_ID)
                user_id    = _get_meta(context, META_USER_ID)
                caller_svc = _get_meta(context, META_CALLER_SVC)

                start = time.perf_counter()
                bound_log = logger.bind(
                    grpc_method=method,
                    request_id=request_id,
                    trace_id=trace_id,
                    user_id=user_id,
                    caller_service=caller_svc,
                )
                bound_log.debug("grpc_call_started")

                result = func(request, context)

                duration_ms = (time.perf_counter() - start) * 1000
                code = context.code() or grpc.StatusCode.OK
                log_fn = bound_log.error if code != grpc.StatusCode.OK else bound_log.info
                log_fn(
                    "grpc_call_completed",
                    grpc_code=code.name,
                    duration_ms=round(duration_ms, 2),
                )
                return result
            return wrapper

        if handler.unary_unary:
            return handler._replace(unary_unary=wrap(handler.unary_unary))
        if handler.unary_stream:
            return handler._replace(unary_stream=wrap(handler.unary_stream))
        return handler


# ---------------------------------------------------------------------------
# Tracing interceptor (OpenTelemetry)
# ---------------------------------------------------------------------------

class ServerTracingInterceptor(_BaseInterceptor):
    """Creates an OTel span for each incoming RPC and propagates trace IDs."""

    def __init__(self, service_name: str) -> None:
        self._tracer = trace.get_tracer(service_name)

    def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        method = self._method_name(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        tracer = self._tracer

        def wrap(func: Callable) -> Callable:
            def wrapper(request: Any, context: grpc.ServicerContext) -> Any:
                with tracer.start_as_current_span(method) as span:
                    span.set_attribute("rpc.system", "grpc")
                    span.set_attribute("rpc.method", method)
                    span.set_attribute(
                        "request_id",
                        _get_meta(context, META_REQUEST_ID, "")
                    )

                    result = func(request, context)

                    code = context.code() or grpc.StatusCode.OK
                    if code != grpc.StatusCode.OK:
                        span.set_status(StatusCode.ERROR, context.details() or "")
                    else:
                        span.set_status(StatusCode.OK)

                    return result
            return wrapper

        if handler.unary_unary:
            return handler._replace(unary_unary=wrap(handler.unary_unary))
        return handler


# ---------------------------------------------------------------------------
# Auth interceptor
# ---------------------------------------------------------------------------

class ServerAuthInterceptor(_BaseInterceptor):
    """Validates JWT bearer token by calling IAM service ValidateToken RPC.

    Args:
        iam_stub: IAMServiceStub connected to the IAM gRPC server.
        public_methods: Set of full method paths that skip auth.
    """

    def __init__(self, iam_stub: Any, public_methods: set[str] | None = None) -> None:
        self._iam = iam_stub
        self._public = set(public_methods or [])
        # Default public methods for ML service (health + metrics)
        self._public.update({
            "/fraud.ml.v1.FraudMLService/HealthCheck",
            "/grpc.health.v1.Health/Check",
        })

    def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        method = self._method_name(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler

        if method in self._public:
            return handler

        iam = self._iam

        def wrap(func: Callable) -> Callable:
            def wrapper(request: Any, context: grpc.ServicerContext) -> Any:
                token = _extract_bearer_token(context)
                if not token:
                    context.abort(
                        grpc.StatusCode.UNAUTHENTICATED,
                        "missing authorization token",
                    )
                    return None

                try:
                    from proto.gen.python.iam.v1 import iam_pb2  # noqa: PLC0415
                    resp = iam.ValidateToken(
                        iam_pb2.ValidateTokenRequest(access_token=token)
                    )
                    if not resp.valid:
                        context.abort(
                            grpc.StatusCode.UNAUTHENTICATED,
                            f"invalid token: {resp.error_code}",
                        )
                        return None
                except grpc.RpcError as exc:
                    logger.error(
                        "iam_validate_failed",
                        method=method,
                        grpc_error=str(exc),
                    )
                    context.abort(
                        grpc.StatusCode.UNAUTHENTICATED,
                        "token validation unavailable",
                    )
                    return None

                return func(request, context)
            return wrapper

        if handler.unary_unary:
            return handler._replace(unary_unary=wrap(handler.unary_unary))
        return handler
