// Package grpc wires up the gRPC server for the IAM service.
//
// NOTE: Proto-generated stubs must be generated before registering RPC handlers.
// Run `make proto` from the repository root to generate the code, then
// register the service implementation by replacing the TODO below.
package grpc

import (
	"context"
	"fmt"
	"net"

	iamv1 "github.com/fraud-detection/proto/gen/go/iam/v1"
	"github.com/fraud-detection/iam-service/internal/service"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
)

// Server wraps the gRPC server and its dependencies.
type Server struct {
	authSvc    *service.AuthService
	tokenSvc   *service.TokenService
	grpcServer *googlegrpc.Server
	log        zerolog.Logger
}

// NewServer constructs a Server and registers all interceptors.
// authSvc is the core business logic; tokenSvc is used for token validation
// inside the shared auth interceptor.
func NewServer(authSvc *service.AuthService, tokenSvc *service.TokenService, log zerolog.Logger) *Server {
	s := &Server{
		authSvc:  authSvc,
		tokenSvc: tokenSvc,
		log:      log,
	}

	// Build a validateToken function that bridges the shared interceptor
	// interface to the IAM token service.
	validateFn := func(ctx context.Context, token string) (userID, role string, permissions []string, err error) {
		claims, err := authSvc.ValidateToken(ctx, token)
		if err != nil {
			return "", "", nil, err
		}
		perms := make([]string, len(claims.Permissions))
		for i, p := range claims.Permissions {
			perms[i] = p.String()
		}
		return claims.UserID, string(claims.Role), perms, nil
	}

	// Public methods that skip JWT authentication.
	// These match the full gRPC method path: /package.ServiceName/MethodName
	publicMethods := []string{
		"/iam.v1.AuthService/Login",
		"/iam.v1.AuthService/Register",
		"/iam.v1.AuthService/VerifyMFA",
		"/iam.v1.AuthService/RefreshTokens",
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "iam-service",
		Log:           log,
		ValidateToken: validateFn,
		PublicMethods: publicMethods,
	}

	unaryChain := middleware.UnaryServerInterceptorChain(interceptorCfg)
	streamChain := middleware.StreamServerInterceptorChain(interceptorCfg)

	s.grpcServer = googlegrpc.NewServer(
		googlegrpc.ChainUnaryInterceptor(unaryChain...),
		googlegrpc.ChainStreamInterceptor(streamChain...),
	)

	// Register the IAMService gRPC handler.
	iamv1.RegisterIAMServiceServer(s.grpcServer, NewAuthHandler(authSvc, tokenSvc, log))

	return s
}

// Run starts listening on the given port and blocks until ctx is cancelled.
// Performs a graceful stop on context cancellation.
func (s *Server) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	log := logger.FromContext(ctx).With().Str("component", "grpc_server").Int("port", port).Logger()
	log.Info().Msg("gRPC server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			errCh <- fmt.Errorf("grpc serve: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("context cancelled — stopping gRPC server gracefully")
		s.grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// GrpcServer exposes the underlying *googlegrpc.Server for reflection or testing.
func (s *Server) GrpcServer() *googlegrpc.Server {
	return s.grpcServer
}
