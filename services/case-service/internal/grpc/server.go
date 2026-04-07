// Package grpc wires up the gRPC server for the Case Management Service.
package grpc

import (
	"context"
	"fmt"
	"net"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	casev1 "github.com/fraud-detection/proto/gen/go/case/v1"
	"github.com/fraud-detection/case-service/internal/service"
	"github.com/fraud-detection/shared/middleware"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
)

// Server wraps the gRPC server for the Case Service.
type Server struct {
	grpcSrv *googlegrpc.Server
	log     zerolog.Logger
}

// New constructs the gRPC Server with JWT middleware.
func New(svc *service.CaseService, log zerolog.Logger, jwtSecret string) *Server {
	s := &Server{log: log}

	publicMethods := []string{
		casev1.CaseService_HealthCheck_FullMethodName,
	}

	var validateFn func(ctx context.Context, token string) (string, string, []string, error)
	if jwtSecret != "" {
		validateFn = makeTokenValidator(jwtSecret)
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "case-service",
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

	casev1.RegisterCaseServiceServer(s.grpcSrv, NewHandler(svc, log))
	return s
}

// Run listens on the given port and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.log.Info().Int("port", port).Msg("case-service gRPC server listening")

	errCh := make(chan error, 1)
	go func() {
		if serveErr := s.grpcSrv.Serve(lis); serveErr != nil {
			errCh <- fmt.Errorf("grpc serve: %w", serveErr)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.log.Info().Msg("context cancelled — stopping case gRPC server")
		s.grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

func makeTokenValidator(jwtSecret string) func(ctx context.Context, token string) (string, string, []string, error) {
	key := []byte(jwtSecret)
	return func(_ context.Context, token string) (string, string, []string, error) {
		parsed, err := jwtv5.ParseWithClaims(token, &jwtv5.MapClaims{},
			func(t *jwtv5.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwtv5.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return key, nil
			},
			jwtv5.WithExpirationRequired(),
		)
		if err != nil {
			return "", "", nil, fmt.Errorf("invalid token: %w", err)
		}
		claims, ok := parsed.Claims.(*jwtv5.MapClaims)
		if !ok || !parsed.Valid {
			return "", "", nil, fmt.Errorf("malformed claims")
		}
		uid, _ := (*claims)["uid"].(string)
		if uid == "" {
			uid, _ = (*claims)["sub"].(string)
		}
		role, _ := (*claims)["role"].(string)
		return uid, role, nil, nil
	}
}
