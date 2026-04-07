package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	"github.com/rs/zerolog"
)

type Server struct {
	httpServer *http.Server
	log        zerolog.Logger
}

func NewServer(cfg appconfig.Config, handler *Handler, log zerolog.Logger) *Server {
	mux := http.NewServeMux()
	handler.Register(mux)

	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler:      mux,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  60 * time.Second,
		},
		log: log.With().Str("component", "http_server").Logger(),
	}
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info().Str("addr", s.httpServer.Addr).Msg("blockchain service http server listening")
		errCh <- s.httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
