// Package middleware provides shared gRPC interceptors for all Go services.
// Every service registers these interceptors at server and client startup.
//
// Server interceptors (apply to incoming calls):
//   - UnaryServerInterceptorChain  → logging + tracing + recovery + auth
//   - StreamServerInterceptorChain → same, for streaming RPCs
//
// Client interceptors (apply to outgoing calls):
//   - UnaryClientInterceptorChain  → request-ID propagation + tracing
package middleware

import (
	"context"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/tracing"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Metadata keys (lowercase per gRPC spec)
// =============================================================================

const (
	MetaKeyRequestID = "x-request-id"
	MetaKeyTraceID   = "x-trace-id"
	MetaKeySpanID    = "x-span-id"
	MetaKeyUserID    = "x-user-id"
	MetaKeyRole      = "x-user-role"
	MetaKeyCallerSvc = "x-caller-service"
	MetaKeyAuthToken = "authorization"
)

// =============================================================================
// Context keys (unexported, prevents collision with other packages)
// =============================================================================

type ctxKey struct{ name string }

var (
	CtxRequestID = ctxKey{"request_id"}
	CtxUserID    = ctxKey{"user_id"}
	CtxUserRole  = ctxKey{"user_role"}
)

// RequestIDFromCtx retrieves the request ID stored in context.
func RequestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(CtxRequestID).(string); ok {
		return id
	}
	return ""
}

// UserIDFromCtx retrieves the user ID from context (set by auth interceptor).
func UserIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(CtxUserID).(string); ok {
		return id
	}
	return ""
}

// =============================================================================
// SERVER INTERCEPTORS
// =============================================================================

// UnaryServerLoggingInterceptor logs every incoming unary RPC with duration,
// status code, and trace context. Uses structured zerolog JSON output.
func UnaryServerLoggingInterceptor(log zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		// Extract / generate request ID
		requestID := extractOrGenerateRequestID(ctx)
		ctx = context.WithValue(ctx, CtxRequestID, requestID)

		// Enrich logger with call metadata
		callLog := log.With().
			Str("grpc.method", info.FullMethod).
			Str("request_id", requestID).
			Str("trace_id", tracing.TraceID(ctx)).
			Str("span_id", tracing.SpanID(ctx)).
			Logger()

		ctx = logger.WithContext(ctx, callLog)
		callLog.Debug().Msg("gRPC call started")

		resp, err := handler(ctx, req)

		// Log outcome
		duration := time.Since(start)
		code := status.Code(err)

		event := callLog.Info()
		if err != nil {
			event = callLog.Error().Err(err)
		}
		event.
			Str("grpc.code", code.String()).
			Dur("duration_ms", duration).
			Msg("gRPC call completed")

		return resp, err
	}
}

// UnaryServerTracingInterceptor creates a child span for every incoming RPC.
func UnaryServerTracingInterceptor(serviceName string) grpc.UnaryServerInterceptor {
	tracer := tracing.Tracer(serviceName)
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx, span := tracer.Start(ctx, info.FullMethod)// Mark as RPC server span

		defer span.End()

		span.SetAttributes(
			semconv.RPCSystemGRPC,
			attribute.String("rpc.method", info.FullMethod),
			attribute.String("request_id", extractOrGenerateRequestID(ctx)),
		)

		resp, err := handler(ctx, req)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(otelcodes.Error, err.Error())
		} else {
			span.SetStatus(otelcodes.Ok, "")
		}
		return resp, err
	}
}

// UnaryServerRecoveryInterceptor catches panics and converts them to gRPC
// INTERNAL errors, preventing service crashes from propagating.
func UnaryServerRecoveryInterceptor(log zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Str("method", info.FullMethod).
					Msg("gRPC handler panicked — recovered")

				err = status.Errorf(codes.Internal,
					"internal server error — request ID: %s", RequestIDFromCtx(ctx))
			}
		}()
		return handler(ctx, req)
	}
}

// UnaryServerAuthInterceptor validates the JWT bearer token on protected RPCs.
// Skips validation for explicitly public methods listed in publicMethods.
// Calls the IAM service ValidateToken RPC for token verification.
func UnaryServerAuthInterceptor(
	log zerolog.Logger,
	validateFn func(ctx context.Context, token string) (userID, role string, permissions []string, err error),
	publicMethods []string,
) grpc.UnaryServerInterceptor {
	publicSet := make(map[string]struct{}, len(publicMethods))
	for _, m := range publicMethods {
		publicSet[m] = struct{}{}
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if _, ok := publicSet[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		// Extract Bearer token from metadata
		token, err := extractBearerToken(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
		}

		// Validate token via IAM service
		userID, role, _, err := validateFn(ctx, token)
		if err != nil {
			callLog := logger.FromContext(ctx)
			callLog.Warn().
				Str("method", info.FullMethod).
				Err(err).
				Msg("token validation failed")
			return nil, status.Errorf(codes.Unauthenticated, "invalid or expired token")
		}

		// Inject identity into context for downstream handlers
		ctx = context.WithValue(ctx, CtxUserID, userID)
		ctx = context.WithValue(ctx, CtxUserRole, role)

		return handler(ctx, req)
	}
}

// UnaryServerMetadataPropagatorInterceptor reads gRPC metadata and injects
// request-id, trace-id, user-id into the context for all handlers.
func UnaryServerMetadataPropagatorInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if ids := md.Get(MetaKeyRequestID); len(ids) > 0 {
				ctx = context.WithValue(ctx, CtxRequestID, ids[0])
			}
			if uids := md.Get(MetaKeyUserID); len(uids) > 0 {
				ctx = context.WithValue(ctx, CtxUserID, uids[0])
			}
			if roles := md.Get(MetaKeyRole); len(roles) > 0 {
				ctx = context.WithValue(ctx, CtxUserRole, roles[0])
			}
		}
		return handler(ctx, req)
	}
}

// =============================================================================
// CLIENT INTERCEPTORS
// =============================================================================

// UnaryClientTracingInterceptor propagates trace context and request metadata
// on every outgoing gRPC call from one service to another.
func UnaryClientTracingInterceptor(callerServiceName string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Inject metadata into outgoing context
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		// Propagate request ID
		if reqID := RequestIDFromCtx(ctx); reqID != "" {
			md.Set(MetaKeyRequestID, reqID)
		}

		// Propagate trace IDs
		if traceID := tracing.TraceID(ctx); traceID != "" {
			md.Set(MetaKeyTraceID, traceID)
		}
		if spanID := tracing.SpanID(ctx); spanID != "" {
			md.Set(MetaKeySpanID, spanID)
		}

		// Identify calling service
		md.Set(MetaKeyCallerSvc, callerServiceName)

		// Propagate user identity if present
		if userID := UserIDFromCtx(ctx); userID != "" {
			md.Set(MetaKeyUserID, userID)
		}

		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// UnaryClientLoggingInterceptor logs outgoing gRPC calls for debugging.
func UnaryClientLoggingInterceptor(log zerolog.Logger) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)

		log.Debug().
			Str("grpc.method", method).
			Str("grpc.code", status.Code(err).String()).
			Dur("duration_ms", time.Since(start)).
			Str("request_id", RequestIDFromCtx(ctx)).
			Err(err).
			Msg("gRPC client call")

		return err
	}
}

// =============================================================================
// STREAM INTERCEPTORS
// =============================================================================

// StreamServerLoggingInterceptor logs stream RPC lifecycle events.
func StreamServerLoggingInterceptor(log zerolog.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		ctx := ss.Context()

		requestID := extractOrGenerateRequestID(ctx)
		callLog := log.With().
			Str("grpc.method", info.FullMethod).
			Str("request_id", requestID).
			Bool("is_client_stream", info.IsClientStream).
			Bool("is_server_stream", info.IsServerStream).
			Logger()

		callLog.Debug().Msg("gRPC stream opened")

		err := handler(srv, ss)

		callLog.Info().
			Str("grpc.code", status.Code(err).String()).
			Dur("duration_ms", time.Since(start)).
			Err(err).
			Msg("gRPC stream closed")

		return err
	}
}

// StreamServerRecoveryInterceptor catches panics in stream handlers.
func StreamServerRecoveryInterceptor(log zerolog.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Str("method", info.FullMethod).
					Msg("gRPC stream handler panicked — recovered")
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(srv, ss)
	}
}

// =============================================================================
// Chain helpers — convenience wrappers
// =============================================================================

// ServerInterceptorConfig holds options for the interceptor chain.
type ServerInterceptorConfig struct {
	ServiceName   string
	Log           zerolog.Logger
	ValidateToken func(ctx context.Context, token string) (userID, role string, permissions []string, err error)
	PublicMethods []string // gRPC method names that skip JWT auth
}

// UnaryServerInterceptorChain returns the ordered chain of unary interceptors.
// Order (outermost first):
//  1. Recovery (catch panics first so nothing leaks)
//  2. Metadata propagation (extract request-id, user-id early)
//  3. Tracing (needs metadata from step 2)
//  4. Logging (needs trace IDs from step 3)
//  5. Auth (needs logging context from step 4)
func UnaryServerInterceptorChain(cfg ServerInterceptorConfig) []grpc.UnaryServerInterceptor {
	chain := []grpc.UnaryServerInterceptor{
		UnaryServerRecoveryInterceptor(cfg.Log),
		UnaryServerMetadataPropagatorInterceptor(),
		UnaryServerTracingInterceptor(cfg.ServiceName),
		UnaryServerLoggingInterceptor(cfg.Log),
	}
	if cfg.ValidateToken != nil {
		chain = append(chain, UnaryServerAuthInterceptor(cfg.Log, cfg.ValidateToken, cfg.PublicMethods))
	}
	return chain
}

// StreamServerInterceptorChain returns the ordered chain of stream interceptors.
func StreamServerInterceptorChain(cfg ServerInterceptorConfig) []grpc.StreamServerInterceptor {
	return []grpc.StreamServerInterceptor{
		StreamServerRecoveryInterceptor(cfg.Log),
		StreamServerLoggingInterceptor(cfg.Log),
	}
}

// ClientInterceptorChain returns the ordered chain of client interceptors.
func ClientInterceptorChain(callerServiceName string, log zerolog.Logger) []grpc.UnaryClientInterceptor {
	return []grpc.UnaryClientInterceptor{
		UnaryClientTracingInterceptor(callerServiceName),
		UnaryClientLoggingInterceptor(log),
	}
}

// =============================================================================
// Internal helpers
// =============================================================================

func extractOrGenerateRequestID(ctx context.Context) string {
	// Check context first
	if id, ok := ctx.Value(CtxRequestID).(string); ok && id != "" {
		return id
	}
	// Check incoming gRPC metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ids := md.Get(MetaKeyRequestID); len(ids) > 0 && ids[0] != "" {
			return ids[0]
		}
	}
	// Generate new UUID
	return uuid.New().String()
}

func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata")
	}

	values := md.Get(MetaKeyAuthToken)
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "no authorization header")
	}

	token := values[0]
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[7:]
	}
	if token == "" {
		return "", status.Error(codes.Unauthenticated, "empty token")
	}
	return token, nil
}
