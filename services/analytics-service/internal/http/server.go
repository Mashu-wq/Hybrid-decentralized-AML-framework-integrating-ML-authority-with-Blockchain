package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/fraud-detection/analytics-service/internal/domain"
	"github.com/fraud-detection/analytics-service/internal/service"
)

// Server exposes REST analytics endpoints used by the Streamlit dashboard.
type Server struct {
	srv *http.Server
	svc *service.AnalyticsService
	log zerolog.Logger
}

// New constructs an HTTP Server on the given port.
func New(svc *service.AnalyticsService, log zerolog.Logger, port int) *Server {
	s := &Server{svc: svc, log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)

	// Analytics REST API
	mux.HandleFunc("GET /api/v1/analytics/trends",              s.handleFraudTrends)
	mux.HandleFunc("GET /api/v1/analytics/risk-distribution",   s.handleRiskDistribution)
	mux.HandleFunc("GET /api/v1/analytics/top-customers",       s.handleTopCustomers)
	mux.HandleFunc("GET /api/v1/analytics/alert-metrics",       s.handleAlertMetrics)
	mux.HandleFunc("GET /api/v1/analytics/transaction-volume",  s.handleTransactionVolume)
	mux.HandleFunc("GET /api/v1/analytics/geo-distribution",    s.handleGeoDistribution)
	mux.HandleFunc("GET /api/v1/analytics/model-performance",   s.handleModelPerformance)
	mux.HandleFunc("GET /api/v1/analytics/report",              s.handleReport)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.srv.Addr, err)
	}
	s.log.Info().Str("addr", s.srv.Addr).Msg("analytics-service HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pgOK, mongoOK, pgErr, mongoErr := s.svc.HealthCheck(ctx)

	status := "ok"
	checks := map[string]string{"postgres": "ok", "mongodb": "ok"}
	if !pgOK {
		status = "degraded"
		checks["postgres"] = pgErr.Error()
	}
	if !mongoOK {
		status = "degraded"
		checks["mongodb"] = mongoErr.Error()
	}

	code := http.StatusOK
	if status != "ok" {
		code = http.StatusServiceUnavailable
	}
	s.writeJSON(w, code, map[string]any{"status": status, "checks": checks})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/trends
// Query params: period=7d|24h|30d  granularity=hour|day|week|month
// ---------------------------------------------------------------------------

func (s *Server) handleFraudTrends(w http.ResponseWriter, r *http.Request) {
	q    := r.URL.Query()
	gran := domain.Granularity(q.Get("granularity"))
	if gran == "" {
		gran = domain.GranularityDay
	}

	// Use named period OR explicit start/end
	var from, to time.Time
	if period := q.Get("period"); period != "" {
		var err error
		from, to, err = domain.PeriodRange(period)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		from = parseTime(q.Get("start"), time.Now().UTC().Add(-7*24*time.Hour))
		to   = parseTime(q.Get("end"),   time.Now().UTC())
	}

	result, err := s.svc.GetFraudTrends(r.Context(), from, to, gran)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type point struct {
		Date         string  `json:"date"`
		AlertCount   int     `json:"alert_count"`
		FraudCount   int     `json:"fraud_count"`
		TotalTxCount int     `json:"total_tx_count"`
		FraudRate    float64 `json:"fraud_rate"`
		AvgFraudProb float64 `json:"avg_fraud_prob"`
	}
	pts := make([]point, len(result.Points))
	for i, p := range result.Points {
		pts[i] = point{
			Date:         p.Date.Format("2006-01-02"),
			AlertCount:   p.AlertCount,
			FraudCount:   p.FraudCount,
			TotalTxCount: p.TotalTxCount,
			FraudRate:    p.FraudRate,
			AvgFraudProb: p.AvgFraudProb,
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"period":      result.Period,
		"granularity": string(result.Granularity),
		"points":      pts,
	})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/risk-distribution
// Query params: period=7d|24h|30d
// ---------------------------------------------------------------------------

func (s *Server) handleRiskDistribution(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "7d"
	}
	buckets, err := s.svc.GetRiskDistribution(r.Context(), period)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"period": period, "buckets": buckets})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/top-customers
// Query params: period=7d  limit=10
// ---------------------------------------------------------------------------

func (s *Server) handleTopCustomers(w http.ResponseWriter, r *http.Request) {
	q      := r.URL.Query()
	period := q.Get("period")
	if period == "" {
		period = "7d"
	}
	limit := 10
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	customers, err := s.svc.GetTopRiskyCustomers(r.Context(), period, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"period": period, "customers": customers})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/alert-metrics
// Query params: period=24h|7d|30d
// ---------------------------------------------------------------------------

func (s *Server) handleAlertMetrics(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	metrics, err := s.svc.GetAlertMetrics(r.Context(), period)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, metrics)
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/transaction-volume
// Query params: period=7d  granularity=day
// ---------------------------------------------------------------------------

func (s *Server) handleTransactionVolume(w http.ResponseWriter, r *http.Request) {
	q    := r.URL.Query()
	gran := domain.Granularity(q.Get("granularity"))
	if gran == "" {
		gran = domain.GranularityDay
	}

	var from, to time.Time
	if period := q.Get("period"); period != "" {
		var err error
		from, to, err = domain.PeriodRange(period)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		from = parseTime(q.Get("start"), time.Now().UTC().Add(-7*24*time.Hour))
		to   = parseTime(q.Get("end"),   time.Now().UTC())
	}

	points, err := s.svc.GetTransactionVolume(r.Context(), from, to, gran)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type vpoint struct {
		Date        string  `json:"date"`
		TxCount     int     `json:"total_count"`
		TotalAmount float64 `json:"total_volume"`
		AvgAmount   float64 `json:"avg_amount"`
		FraudCount  int     `json:"flagged_count"`
	}
	pts := make([]vpoint, len(points))
	for i, p := range points {
		pts[i] = vpoint{
			Date:        p.Date.Format("2006-01-02"),
			TxCount:     p.TxCount,
			TotalAmount: p.TotalAmount,
			AvgAmount:   p.AvgAmount,
			FraudCount:  p.FraudCount,
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"points": pts})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/geo-distribution
// Query params: period=7d
// ---------------------------------------------------------------------------

func (s *Server) handleGeoDistribution(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "7d"
	}
	points, err := s.svc.GetGeographicDistribution(r.Context(), period)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"period": period, "points": points})
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/model-performance
// Query params: period=7d  model_version=""
// ---------------------------------------------------------------------------

func (s *Server) handleModelPerformance(w http.ResponseWriter, r *http.Request) {
	q            := r.URL.Query()
	period       := q.Get("period")
	modelVersion := q.Get("model_version")
	if period == "" {
		period = "7d"
	}
	perf, err := s.svc.GetModelPerformance(r.Context(), modelVersion, period)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, perf)
}

// ---------------------------------------------------------------------------
// GET /api/v1/analytics/report
// Query params: type=SUMMARY|COMPLIANCE|SAR|MODEL_AUDIT  period=7d
// ---------------------------------------------------------------------------

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	q      := r.URL.Query()
	period := q.Get("period")
	if period == "" {
		period = "7d"
	}
	rtype := domain.ReportType(q.Get("type"))
	if rtype == "" {
		rtype = domain.ReportTypeSummary
	}

	report, err := s.svc.GenerateReport(r.Context(), rtype, period)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, report)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error().Err(err).Msg("JSON encode error")
	}
}

func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]string{"error": msg})
}

func parseTime(s string, fallback time.Time) time.Time {
	if s == "" {
		return fallback
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return fallback
}
