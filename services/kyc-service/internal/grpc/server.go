// Package grpc wires up the gRPC server for the KYC service.
package grpc

import (
	"context"
	"fmt"
	"net"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	kycv1 "github.com/fraud-detection/proto/gen/go/kyc/v1"
	"github.com/fraud-detection/kyc-service/internal/service"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
)

// Server wraps the gRPC server and the KYC service implementation.
type Server struct {
	kycSvc  *service.KYCService
	grpcSrv *googlegrpc.Server
	log     zerolog.Logger
}

// New constructs a Server, registers all interceptors, and registers the
// KYCService gRPC handler. jwtSecret is passed to the auth interceptor for
// service-to-service token validation; pass an empty string to skip JWT auth
// (development / internal network only).
func New(kycSvc *service.KYCService, log zerolog.Logger, jwtSecret string) *Server {
	s := &Server{
		kycSvc: kycSvc,
		log:    log,
	}

	var validateFn func(ctx context.Context, token string) (userID, role string, permissions []string, err error)
	publicMethods := []string{
		kycv1.KYCService_RegisterCustomer_FullMethodName,
		kycv1.KYCService_GetKYCRecord_FullMethodName,
		kycv1.KYCService_GetCustomerRiskLevel_FullMethodName,
		kycv1.KYCService_HealthCheck_FullMethodName,
	}

	if jwtSecret != "" {
		validateFn = makeTokenValidator(jwtSecret)
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "kyc-service",
		Log:           log,
		ValidateToken: validateFn,
		PublicMethods: publicMethods,
	}

	unaryChain := middleware.UnaryServerInterceptorChain(interceptorCfg)
	streamChain := middleware.StreamServerInterceptorChain(interceptorCfg)

	s.grpcSrv = googlegrpc.NewServer(
		googlegrpc.ChainUnaryInterceptor(unaryChain...),
		googlegrpc.ChainStreamInterceptor(streamChain...),
	)

	kycv1.RegisterKYCServiceServer(s.grpcSrv, NewKYCHandler(kycSvc, log))

	return s
}

// Run starts listening on the given port and blocks until ctx is cancelled.
// On context cancellation a graceful stop is attempted.
func (s *Server) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	log := logger.FromContext(ctx).With().
		Str("component", "grpc_server").
		Int("port", port).
		Logger()
	log.Info().Msg("KYC gRPC server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcSrv.Serve(lis); err != nil {
			errCh <- fmt.Errorf("grpc serve: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("context cancelled — stopping gRPC server gracefully")
		s.grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// GrpcServer exposes the underlying *googlegrpc.Server for reflection or testing.
func (s *Server) GrpcServer() *googlegrpc.Server {
	return s.grpcSrv
}

// makeTokenValidator returns a JWT validator that verifies the shared HMAC-SHA256
// secret for service-to-service authentication.
func makeTokenValidator(jwtSecret string) func(ctx context.Context, token string) (string, string, []string, error) {
	key := []byte(jwtSecret)
	return func(ctx context.Context, token string) (userID, role string, permissions []string, err error) {
		parsed, parseErr := jwtv5.ParseWithClaims(
			token,
			&jwtv5.MapClaims{},
			func(t *jwtv5.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwtv5.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return key, nil
			},
			jwtv5.WithExpirationRequired(),
		)
		if parseErr != nil {
			return "", "", nil, fmt.Errorf("invalid token: %w", parseErr)
		}

		claims, ok := parsed.Claims.(*jwtv5.MapClaims)
		if !ok || !parsed.Valid {
			return "", "", nil, fmt.Errorf("malformed token claims")
		}

		uid, _ := (*claims)["uid"].(string)
		r, _ := (*claims)["role"].(string)
		if uid == "" {
			uid, _ = (*claims)["sub"].(string)
		}
		return uid, r, nil, nil
	}
}
