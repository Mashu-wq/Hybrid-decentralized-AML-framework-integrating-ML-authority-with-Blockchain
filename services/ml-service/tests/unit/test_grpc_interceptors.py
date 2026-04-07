"""
Unit tests for gRPC interceptors in the ML service.
No external services required — all stubs are mocked.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import grpc

from app.grpc.interceptors import (
    META_AUTH_TOKEN,
    META_REQUEST_ID,
    META_USER_ID,
    ServerAuthInterceptor,
    ServerLoggingInterceptor,
    ServerRecoveryInterceptor,
    _get_meta,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_context(metadata: dict[str, str] | None = None) -> MagicMock:
    """Create a mock gRPC ServicerContext with given metadata."""
    ctx = MagicMock(spec=grpc.ServicerContext)
    if metadata:
        ctx.invocation_metadata.return_value = list(metadata.items())
    else:
        ctx.invocation_metadata.return_value = []
    ctx.code.return_value = grpc.StatusCode.OK
    return ctx


def _make_handler_details(method: str) -> MagicMock:
    details = MagicMock(spec=grpc.HandlerCallDetails)
    details.method = method
    return details


def _make_rpc_handler(func) -> grpc.RpcMethodHandler:
    return grpc.unary_unary_rpc_method_handler(func)


def _noop_continuation(method_handler):
    def continuation(handler_call_details):
        return method_handler
    return continuation


# ---------------------------------------------------------------------------
# Tests: _get_meta helper
# ---------------------------------------------------------------------------

class TestGetMeta(unittest.TestCase):
    def test_returns_value_when_present(self):
        ctx = _make_context({META_REQUEST_ID: "req-001"})
        result = _get_meta(ctx, META_REQUEST_ID)
        self.assertEqual(result, "req-001")

    def test_returns_default_when_missing(self):
        ctx = _make_context()
        result = _get_meta(ctx, META_REQUEST_ID, default="fallback")
        self.assertEqual(result, "fallback")

    def test_case_insensitive(self):
        ctx = _make_context({"X-Request-ID": "abc"})
        result = _get_meta(ctx, "x-request-id")
        self.assertEqual(result, "abc")


# ---------------------------------------------------------------------------
# Tests: ServerRecoveryInterceptor
# ---------------------------------------------------------------------------

class TestServerRecoveryInterceptor(unittest.TestCase):
    def setUp(self):
        self.interceptor = ServerRecoveryInterceptor()

    def test_passthrough_on_success(self):
        def handler(request, context):
            return "success"

        rpc_handler = _make_rpc_handler(handler)
        intercepted = self.interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/test.Service/OK"),
        )
        ctx = _make_context()
        result = intercepted.unary_unary("req", ctx)
        self.assertEqual(result, "success")

    def test_catches_exception_returns_none(self):
        def panicking_handler(request, context):
            raise RuntimeError("boom!")

        rpc_handler = _make_rpc_handler(panicking_handler)
        intercepted = self.interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/test.Service/Panic"),
        )
        ctx = _make_context({META_REQUEST_ID: "test-req"})
        result = intercepted.unary_unary("req", ctx)

        self.assertIsNone(result)
        ctx.set_code.assert_called_once_with(grpc.StatusCode.INTERNAL)
        ctx.set_details.assert_called_once()
        detail = ctx.set_details.call_args[0][0]
        self.assertIn("test-req", detail)


# ---------------------------------------------------------------------------
# Tests: ServerLoggingInterceptor
# ---------------------------------------------------------------------------

class TestServerLoggingInterceptor(unittest.TestCase):
    def setUp(self):
        import structlog
        self.log = structlog.get_logger()
        self.interceptor = ServerLoggingInterceptor()

    def test_passthrough_result(self):
        def handler(request, context):
            return {"fraud": True}

        rpc_handler = _make_rpc_handler(handler)
        intercepted = self.interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/fraud.ml.v1.FraudMLService/PredictFraud"),
        )
        ctx = _make_context({META_REQUEST_ID: "log-test-1"})
        result = intercepted.unary_unary("req", ctx)
        self.assertEqual(result, {"fraud": True})

    def test_none_handler_passthrough(self):
        intercepted = self.interceptor.intercept_service(
            lambda _: None,
            _make_handler_details("/foo/Bar"),
        )
        self.assertIsNone(intercepted)


# ---------------------------------------------------------------------------
# Tests: ServerAuthInterceptor
# ---------------------------------------------------------------------------

class TestServerAuthInterceptor(unittest.TestCase):
    def _make_interceptor(self, valid: bool = True) -> ServerAuthInterceptor:
        mock_resp = MagicMock()
        mock_resp.valid = valid
        mock_resp.error_code = "" if valid else "TOKEN_EXPIRED"

        mock_iam = MagicMock()
        mock_iam.ValidateToken.return_value = mock_resp

        return ServerAuthInterceptor(
            iam_stub=mock_iam,
            public_methods={"/fraud.ml.v1.FraudMLService/HealthCheck"},
        )

    def test_skips_auth_for_public_method(self):
        interceptor = self._make_interceptor(valid=False)  # even if IAM says invalid

        def handler(request, context):
            return "public_ok"

        rpc_handler = _make_rpc_handler(handler)
        intercepted = interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/fraud.ml.v1.FraudMLService/HealthCheck"),
        )
        ctx = _make_context()  # no token
        result = intercepted.unary_unary("req", ctx)
        self.assertEqual(result, "public_ok")

    def test_rejects_missing_token(self):
        interceptor = self._make_interceptor()

        def handler(request, context):
            return "should_not_reach"

        rpc_handler = _make_rpc_handler(handler)
        intercepted = interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/fraud.ml.v1.FraudMLService/PredictFraud"),
        )
        ctx = _make_context()  # no auth header
        result = intercepted.unary_unary("req", ctx)

        self.assertIsNone(result)
        ctx.abort.assert_called_once_with(
            grpc.StatusCode.UNAUTHENTICATED,
            "missing authorization token",
        )

    def test_accepts_valid_token(self):
        interceptor = self._make_interceptor(valid=True)

        def handler(request, context):
            return "authenticated!"

        rpc_handler = _make_rpc_handler(handler)
        intercepted = interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/fraud.ml.v1.FraudMLService/PredictFraud"),
        )
        ctx = _make_context({META_AUTH_TOKEN: "Bearer valid-token-123"})

        with patch("app.grpc.interceptors.iam_pb2", create=True):
            result = intercepted.unary_unary("req", ctx)

        self.assertEqual(result, "authenticated!")

    def test_rejects_invalid_token(self):
        interceptor = self._make_interceptor(valid=False)

        def handler(request, context):
            return "should_not_reach"

        rpc_handler = _make_rpc_handler(handler)
        intercepted = interceptor.intercept_service(
            _noop_continuation(rpc_handler),
            _make_handler_details("/fraud.ml.v1.FraudMLService/PredictFraud"),
        )
        ctx = _make_context({META_AUTH_TOKEN: "Bearer expired-token"})

        with patch("app.grpc.interceptors.iam_pb2", create=True):
            result = intercepted.unary_unary("req", ctx)

        self.assertIsNone(result)
        ctx.abort.assert_called_once()
        abort_code = ctx.abort.call_args[0][0]
        self.assertEqual(abort_code, grpc.StatusCode.UNAUTHENTICATED)


if __name__ == "__main__":
    unittest.main()
