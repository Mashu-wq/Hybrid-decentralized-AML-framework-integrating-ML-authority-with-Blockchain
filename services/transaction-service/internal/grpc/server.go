// Package grpc wires up the gRPC server for the Transaction Monitoring Service.
package grpc

import (
	"context"
	"fmt"
	"net"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	transactionv1 "github.com/fraud-detection/proto/gen/go/transaction/v1"
	"github.com/fraud-detection/transaction-service/internal/service"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
)

// Server wraps the gRPC server and the transaction service implementation.
type Server struct {
	svc     *service.TransactionService
	grpcSrv *googlegrpc.Server
	log     zerolog.Logger
}

// New constructs a Server, registers all interceptors, and wires the
// TransactionService handler. jwtSecret must be the same HMAC secret used
// by the IAM service to sign service-to-service tokens.
func New(svc *service.TransactionService, log zerolog.Logger, jwtSecret string) *Server {
	s := &Server{svc: svc, log: log}

	// Public methods (no JWT required)
	publicMethods := []string{
		transactionv1.TransactionService_HealthCheck_FullMethodName,
		transactionv1.TransactionService_IngestTransaction_FullMethodName, // open for Kafka bridge clients
	}

	var validateFn func(ctx context.Context, token string) (string, string, []string, error)
	if jwtSecret != "" {
		validateFn = makeTokenValidator(jwtSecret)
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "transaction-service",
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

	transactionv1.RegisterTransactionServiceServer(s.grpcSrv, NewHandler(svc, log))
	return s
}

// Run starts listening on the given port and blocks until ctx is cancelled.
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
	log.Info().Msg("transaction gRPC server listening")

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

// makeTokenValidator returns a JWT HS256 validator for service-to-service auth.
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
