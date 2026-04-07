// Package http implements the REST API for the Alert Service.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fraud-detection/alert-service/internal/domain"
	"github.com/rs/zerolog/log"
)

// AlertServiceInterface is the narrow service contract the HTTP handler depends on.
type AlertServiceInterface interface {
	GetAlert(ctx context.Context, alertID string) (*domain.Alert, error)
	ListAlerts(ctx context.Context, f domain.AlertFilters) ([]*domain.Alert, int, error)
	GetAlertsByCustomer(ctx context.Context, customerID string, limit, offset int) ([]*domain.Alert, error)
	UpdateStatus(ctx context.Context, alertID, changedBy, notes string, newStatus domain.AlertStatus) (*domain.Alert, error)
	AssignAlert(ctx context.Context, alertID, assigneeID string) (*domain.Alert, error)
	EscalateAlert(ctx context.Context, alertID, analystID, reason string) (*domain.Alert, error)
	GetStats(ctx context.Context, period string) (*domain.AlertStats, error)
	HealthCheck(ctx context.Context) map[string]string
}

// Handler handles HTTP requests for the alert REST API.
type Handler struct {
	svc AlertServiceInterface
}

// NewHandler creates a Handler.
func NewHandler(svc AlertServiceInterface) *Handler {
	return &Handler{svc: svc}
}

// ---------------------------------------------------------------------------
// GET /alerts
// ---------------------------------------------------------------------------

func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.AlertFilters{
		Status:    domain.AlertStatus(q.Get("status")),
		AssigneeID: q.Get("assignee_id"),
		SortBy:    q.Get("sort_by"),
		Ascending: q.Get("order") == "asc",
	}

	if p := q.Get("priority"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			f.Priority = domain.AlertPriority(n)
		}
	}
	if v := q.Get("min_fraud_prob"); v != "" {
		if fv, err := strconv.ParseFloat(v, 64); err == nil {
			f.MinFraudProb = fv
		}
	}
	if v := q.Get("start"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.StartTime = t
		}
	}
	if v := q.Get("end"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.EndTime = t
		}
	}
	f.PageSize = intQuery(q.Get("limit"), 50)
	f.Offset = intQuery(q.Get("offset"), 0)

	alerts, total, err := h.svc.ListAlerts(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"alerts": alerts,
		"total":  total,
	})
}

// ---------------------------------------------------------------------------
// GET /alerts/:id
// ---------------------------------------------------------------------------

func (h *Handler) GetAlert(w http.ResponseWriter, r *http.Request) {
	alertID := pathParam(r.URL.Path, "/alerts/")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "alert_id required")
		return
	}

	a, err := h.svc.GetAlert(r.Context(), alertID)
	if err != nil {
		if errors.Is(err, domain.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "alert not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// ---------------------------------------------------------------------------
// GET /alerts/customer/:customer_id
// ---------------------------------------------------------------------------

func (h *Handler) GetAlertsByCustomer(w http.ResponseWriter, r *http.Request) {
	customerID := pathParam(r.URL.Path, "/alerts/customer/")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "customer_id required")
		return
	}
	q := r.URL.Query()
	limit := intQuery(q.Get("limit"), 50)
	offset := intQuery(q.Get("offset"), 0)

	alerts, err := h.svc.GetAlertsByCustomer(r.Context(), customerID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// ---------------------------------------------------------------------------
// PATCH /alerts/:id/status
// ---------------------------------------------------------------------------

type updateStatusRequest struct {
	Status    string `json:"status"`
	ChangedBy string `json:"changed_by"`
	Notes     string `json:"notes"`
}

func (h *Handler) UpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	// Strip /status suffix to get alert_id
	path := strings.TrimSuffix(r.URL.Path, "/status")
	alertID := pathParam(path, "/alerts/")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "alert_id required")
		return
	}

	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}

	changedBy := req.ChangedBy
	if changedBy == "" {
		changedBy = userFromContext(r)
	}

	updated, err := h.svc.UpdateStatus(r.Context(), alertID, changedBy, req.Notes, domain.AlertStatus(req.Status))
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrAlertNotFound):
			writeError(w, http.StatusNotFound, "alert not found")
		case errors.Is(err, domain.ErrInvalidTransition):
			writeError(w, http.StatusUnprocessableEntity, "invalid status transition")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// POST /alerts/:id/assign
// ---------------------------------------------------------------------------

type assignRequest struct {
	AssigneeID string `json:"assignee_id"`
}

func (h *Handler) AssignAlert(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/assign")
	alertID := pathParam(path, "/alerts/")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "alert_id required")
		return
	}

	var req assignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AssigneeID == "" {
		writeError(w, http.StatusBadRequest, "assignee_id required")
		return
	}

	updated, err := h.svc.AssignAlert(r.Context(), alertID, req.AssigneeID)
	if err != nil {
		if errors.Is(err, domain.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "alert not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// POST /alerts/:id/escalate
// ---------------------------------------------------------------------------

type escalateRequest struct {
	AnalystID string `json:"analyst_id"`
	Reason    string `json:"reason"`
}

func (h *Handler) EscalateAlert(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/escalate")
	alertID := pathParam(path, "/alerts/")
	if alertID == "" {
		writeError(w, http.StatusBadRequest, "alert_id required")
		return
	}

	var req escalateRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "manual escalation via API"
	}

	updated, err := h.svc.EscalateAlert(r.Context(), alertID, req.AnalystID, req.Reason)
	if err != nil {
		if errors.Is(err, domain.ErrAlertNotFound) {
			writeError(w, http.StatusNotFound, "alert not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// GET /alerts/stats
// ---------------------------------------------------------------------------

func (h *Handler) GetAlertStats(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	stats, err := h.svc.GetStats(r.Context(), period)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := h.svc.HealthCheck(r.Context())
	overall := "ok"
	for _, v := range status {
		if v != "ok" {
			overall = "degraded"
			break
		}
	}
	code := http.StatusOK
	if overall != "ok" {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": overall, "checks": status})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("JSON encode error")
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func pathParam(path, prefix string) string {
	s := strings.TrimPrefix(path, prefix)
	s = strings.TrimPrefix(s, "/")
	return strings.Split(s, "/")[0]
}

func intQuery(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}

func userFromContext(r *http.Request) string {
	if v := r.Header.Get("X-User-ID"); v != "" {
		return v
	}
	return "unknown"
}
