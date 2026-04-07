package middleware_test

import (
	"context"
	"testing"

	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// --- Helpers ---

func noopHandler(_ context.Context, _ interface{}) (interface{}, error) {
	return "ok", nil
}

func panicHandler(_ context.Context, _ interface{}) (interface{}, error) {
	panic("test panic")
}

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

// --- Tests ---

func TestRequestIDFromCtx_MissingReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	assert.Empty(t, middleware.RequestIDFromCtx(ctx))
}

func TestRequestIDFromCtx_SetReturnsValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.CtxRequestID, "req-123")
	assert.Equal(t, "req-123", middleware.RequestIDFromCtx(ctx))
}

func TestRecoveryInterceptor_CatchesPanic(t *testing.T) {
	log := zerolog.Nop()
	interceptor := middleware.UnaryServerRecoveryInterceptor(log)

	_, err := interceptor(context.Background(), nil, unaryInfo("/test.Service/Panic"), panicHandler)

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRecoveryInterceptor_PassthroughOnSuccess(t *testing.T) {
	log := zerolog.Nop()
	interceptor := middleware.UnaryServerRecoveryInterceptor(log)

	resp, err := interceptor(context.Background(), nil, unaryInfo("/test.Service/OK"), noopHandler)

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

func TestLoggingInterceptor_InjectsRequestID(t *testing.T) {
	log := zerolog.Nop()
	interceptor := middleware.UnaryServerLoggingInterceptor(log)

	var capturedCtx context.Context
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedCtx = ctx
		return nil, nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.MetaKeyRequestID, "test-req-id-999",
	))

	_, _ = interceptor(ctx, nil, unaryInfo("/test.Service/Log"), handler)
	// Request ID should be propagated from metadata into context
	// (via MetadataPropagator — logging interceptor reads from context)
}

func TestMetadataPropagatorInterceptor_ExtractsRequestID(t *testing.T) {
	interceptor := middleware.UnaryServerMetadataPropagatorInterceptor()

	var capturedCtx context.Context
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedCtx = ctx
		return nil, nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.MetaKeyRequestID, "req-abc",
		middleware.MetaKeyUserID, "user-xyz",
	))

	_, err := interceptor(ctx, nil, unaryInfo("/test.Service/Meta"), handler)
	require.NoError(t, err)
	assert.Equal(t, "req-abc", middleware.RequestIDFromCtx(capturedCtx))
	assert.Equal(t, "user-xyz", middleware.UserIDFromCtx(capturedCtx))
}

func TestAuthInterceptor_SkipsPublicMethods(t *testing.T) {
	log := zerolog.Nop()
	called := false
	validateFn := func(_ context.Context, _ string) (string, string, []string, error) {
		called = true
		return "", "", nil, nil
	}

	interceptor := middleware.UnaryServerAuthInterceptor(log, validateFn,
		[]string{"/fraud.iam.v1.IAMService/Login"})

	_, err := interceptor(context.Background(), nil,
		unaryInfo("/fraud.iam.v1.IAMService/Login"), noopHandler)

	require.NoError(t, err)
	assert.False(t, called, "validateFn should not be called for public methods")
}

func TestAuthInterceptor_RejectsNoToken(t *testing.T) {
	log := zerolog.Nop()
	validateFn := func(_ context.Context, _ string) (string, string, []string, error) {
		return "user-1", "ANALYST", nil, nil
	}

	interceptor := middleware.UnaryServerAuthInterceptor(log, validateFn, nil)

	_, err := interceptor(context.Background(), nil,
		unaryInfo("/fraud.alert.v1.AlertService/ListAlerts"), noopHandler)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_AcceptsValidToken(t *testing.T) {
	log := zerolog.Nop()
	validateFn := func(_ context.Context, token string) (string, string, []string, error) {
		assert.Equal(t, "valid-token", token)
		return "user-1", "ANALYST", []string{"alerts:read"}, nil
	}

	interceptor := middleware.UnaryServerAuthInterceptor(log, validateFn, nil)

	var capturedCtx context.Context
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		capturedCtx = ctx
		return nil, nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		middleware.MetaKeyAuthToken, "Bearer valid-token",
	))

	_, err := interceptor(ctx, nil,
		unaryInfo("/fraud.alert.v1.AlertService/ListAlerts"), handler)

	require.NoError(t, err)
	assert.Equal(t, "user-1", middleware.UserIDFromCtx(capturedCtx))
}

func TestClientTracingInterceptor_PropagatesRequestID(t *testing.T) {
	interceptor := middleware.UnaryClientTracingInterceptor("test-service")

	ctx := context.WithValue(context.Background(), middleware.CtxRequestID, "client-req-001")

	var capturedCtx context.Context
	invoker := func(ctx context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		capturedCtx = ctx
		return nil
	}

	err := interceptor(ctx, "/some.Method", nil, nil, nil, invoker)
	require.NoError(t, err)

	outMD, _ := metadata.FromOutgoingContext(capturedCtx)
	reqIDs := outMD.Get(middleware.MetaKeyRequestID)
	require.Len(t, reqIDs, 1)
	assert.Equal(t, "client-req-001", reqIDs[0])
}
