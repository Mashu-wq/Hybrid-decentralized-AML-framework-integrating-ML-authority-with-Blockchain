// Package grpc wires up the gRPC server for the encryption service.
package grpc

import (
	"context"
	"fmt"
	"net"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"

	encryptionv1 "github.com/fraud-detection/proto/gen/go/encryption/v1"
	"github.com/fraud-detection/encryption-service/internal/service"
	"github.com/fraud-detection/shared/logger"
	"github.com/fraud-detection/shared/middleware"
)

// Server wraps the gRPC server and the encryption service implementation.
type Server struct {
	encSvc  *service.EncryptionService
	grpcSrv *googlegrpc.Server
	log     zerolog.Logger
}

// New constructs a Server, registers all interceptors, and registers the
// EncryptionService handler. jwtSecret is passed to the auth interceptor for
// service-to-service token validation; pass an empty string to skip JWT auth
// (development / internal network only).
func New(encSvc *service.EncryptionService, log zerolog.Logger, jwtSecret string) *Server {
	s := &Server{
		encSvc: encSvc,
		log:    log,
	}

	// All encryption service methods are internal-only; there are no
	// publicly-accessible endpoints that require different auth treatment.
	// If jwtSecret is set, all methods will require a valid bearer token.
	var validateFn func(ctx context.Context, token string) (userID, role string, permissions []string, err error)
	var publicMethods []string

	if jwtSecret != "" {
		validateFn = makeTokenValidator(jwtSecret)
		// HealthCheck is publicly accessible for liveness probes.
		publicMethods = []string{
			encryptionv1.EncryptionService_HealthCheck_FullMethodName,
		}
	}

	interceptorCfg := middleware.ServerInterceptorConfig{
		ServiceName:   "encryption-service",
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

	encryptionv1.RegisterEncryptionServiceServer(s.grpcSrv, encSvc)

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
	log.Info().Msg("encryption gRPC server listening")

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

// jwtServiceClaims holds the minimal claims for service-to-service tokens.
type jwtServiceClaims struct {
	UserID string `json:"uid"`
	Role   string `json:"role"`
}

func (c *jwtServiceClaims) GetExpirationTime() (*jwtv5.NumericDate, error) { return nil, nil }
func (c *jwtServiceClaims) GetIssuedAt() (*jwtv5.NumericDate, error)       { return nil, nil }
func (c *jwtServiceClaims) GetNotBefore() (*jwtv5.NumericDate, error)      { return nil, nil }
func (c *jwtServiceClaims) GetIssuer() (string, error)                     { return "", nil }
func (c *jwtServiceClaims) GetSubject() (string, error)                    { return c.UserID, nil }
func (c *jwtServiceClaims) GetAudience() (jwtv5.ClaimStrings, error)       { return nil, nil }

// makeTokenValidator returns a JWT validator that verifies the shared HMAC-SHA256
// secret. The encryption service does not perform permission checks — it only
// confirms the token was signed by the system (i.e., the caller is a trusted
// internal service).
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
