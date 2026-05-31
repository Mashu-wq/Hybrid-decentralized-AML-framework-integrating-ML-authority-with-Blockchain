// Package grpc wires up the gRPC server for the Analytics Service.
package grpc

import (
	"context"
	"fmt"
	"net"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	analyticsv1 "github.com/fraud-detection/proto/gen/go/analytics/v1"
	"github.com/fraud-detection/analytics-service/internal/service"
	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
)

// Server wraps the gRPC server and the analytics service handler.
type Server struct {
	grpcSrv *googlegrpc.Server
	log     zerolog.Logger
}

// New constructs the gRPC Server with JWT authentication middleware.
func New(svc *service.AnalyticsService, log zerolog.Logger, jwtSecret string) *Server {
	s := &Server{log: log}

	publicMethods := []string{
		analyticsv1.AnalyticsService_HealthCheck_FullMethodName,
	}

	var validateFn func(ctx context.Context, token string) (string, string, []string, error)
	if jwtSecret != "" {
		validateFn = makeTokenValidator(jwtSecret)
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "analytics-service",
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

	analyticsv1.RegisterAnalyticsServiceServer(s.grpcSrv, NewHandler(svc, log))
	return s
}

// Run listens on the given port and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	s.log.Info().Int("port", port).Msg("analytics gRPC server listening")

	errCh := make(chan error, 1)
	go func() {
		if serveErr := s.grpcSrv.Serve(lis); serveErr != nil {
			errCh <- fmt.Errorf("grpc serve: %w", serveErr)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.log.Info().Msg("context cancelled — stopping analytics gRPC server")
		s.grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// GrpcServer exposes the underlying server for reflection or testing.
func (s *Server) GrpcServer() *googlegrpc.Server {
	return s.grpcSrv
}

func makeTokenValidator(jwtSecret string) func(ctx context.Context, token string) (string, string, []string, error) {
	key := []byte(jwtSecret)
	return func(_ context.Context, token string) (userID, role string, permissions []string, err error) {
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
