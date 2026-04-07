// Package http implements the REST API for the Case Management Service.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/fraud-detection/case-service/internal/service"
	"github.com/rs/zerolog/log"
)

// CaseServiceInterface is the narrow contract for the REST handler.
type CaseServiceInterface interface {
	CreateCase(ctx context.Context, req *service.CreateCaseInput) (*domain.Case, error)
	GetCase(ctx context.Context, caseID string) (*domain.Case, []*domain.CaseAction, error)
	ListCases(ctx context.Context, f domain.CaseFilters) ([]*domain.Case, int, error)
	UpdateCaseStatus(ctx context.Context, caseID, updatedBy, notes string, newStatus domain.CaseStatus, resolutionSummary string) (*domain.Case, error)
	AssignCase(ctx context.Context, caseID, assigneeID, assignedBy string) (*domain.Case, error)
	AutoAssign(ctx context.Context, caseID, assignedBy string) (*domain.Case, error)
	AddEvidence(ctx context.Context, req *service.AddEvidenceInput) (*domain.Evidence, string, string, error)
	GetEvidence(ctx context.Context, caseID, evidenceID string) ([]*domain.Evidence, []string, error)
	DeleteEvidence(ctx context.Context, caseID, evidenceID, deletedBy string) error
	GenerateSAR(ctx context.Context, caseID, generatedBy, notes string) (string, string, error)
	GetCaseStats(ctx context.Context, period string) (*domain.CaseStats, error)
	GetInvestigatorWorkload(ctx context.Context, ids []string) ([]*domain.InvestigatorWorkload, error)
	HealthCheck(ctx context.Context) map[string]string
}

// Handler handles all REST requests.
type Handler struct {
	svc CaseServiceInterface
}

// NewHandler creates a Handler.
func NewHandler(svc CaseServiceInterface) *Handler {
	return &Handler{svc: svc}
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
// POST /cases
// ---------------------------------------------------------------------------

func (h *Handler) CreateCase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		AlertID          string  `json:"alert_id"`
		CustomerID       string  `json:"customer_id"`
		TxHash           string  `json:"tx_hash"`
		Title            string  `json:"title"`
		Description      string  `json:"description"`
		FraudProbability float64 `json:"fraud_probability"`
		RiskScore        float64 `json:"risk_score"`
		AssigneeID       string  `json:"assignee_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	c, err := h.svc.CreateCase(r.Context(), &service.CreateCaseInput{
		AlertID:          req.AlertID,
		CustomerID:       req.CustomerID,
		TxHash:           req.TxHash,
		Title:            req.Title,
		Description:      req.Description,
		FraudProbability: req.FraudProbability,
		RiskScore:        req.RiskScore,
		AssigneeID:       req.AssigneeID,
	})
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// ---------------------------------------------------------------------------
// GET /cases
// ---------------------------------------------------------------------------

func (h *Handler) ListCases(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.CaseFilters{
		Status:     domain.CaseStatus(q.Get("status")),
		AssigneeID: q.Get("assignee_id"),
		CustomerID: q.Get("customer_id"),
		SortBy:     q.Get("sort_by"),
		Ascending:  q.Get("order") == "asc",
		PageSize:   intQ(q.Get("limit"), 50),
		Offset:     intQ(q.Get("offset"), 0),
	}
	if p := q.Get("priority"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			f.Priority = domain.CasePriority(n)
		}
	}
	cases, total, err := h.svc.ListCases(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cases": cases, "total": total})
}

// ---------------------------------------------------------------------------
// GET /cases/:id
// ---------------------------------------------------------------------------

func (h *Handler) GetCase(w http.ResponseWriter, r *http.Request) {
	caseID := pathParam(r.URL.Path, "/cases/")
	if caseID == "" {
		writeError(w, http.StatusBadRequest, "case_id required")
		return
	}
	c, actions, err := h.svc.GetCase(r.Context(), caseID)
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"case": c, "actions": actions})
}

// ---------------------------------------------------------------------------
// PATCH /cases/:id/status
// ---------------------------------------------------------------------------

func (h *Handler) UpdateCaseStatus(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/status")
	caseID := pathParam(path, "/cases/")
	if caseID == "" {
		writeError(w, http.StatusBadRequest, "case_id required")
		return
	}
	var req struct {
		Status            string `json:"status"`
		UpdatedBy         string `json:"updated_by"`
		Notes             string `json:"notes"`
		ResolutionSummary string `json:"resolution_summary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}
	if req.UpdatedBy == "" {
		req.UpdatedBy = r.Header.Get("X-User-ID")
	}
	updated, err := h.svc.UpdateCaseStatus(r.Context(), caseID, req.UpdatedBy, req.Notes,
		domain.CaseStatus(req.Status), req.ResolutionSummary)
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// POST /cases/:id/assign
// ---------------------------------------------------------------------------

func (h *Handler) AssignCase(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/assign")
	caseID := pathParam(path, "/cases/")
	if caseID == "" {
		writeError(w, http.StatusBadRequest, "case_id required")
		return
	}
	var req struct {
		AssigneeID string `json:"assignee_id"`
		AssignedBy string `json:"assigned_by"`
		Auto       bool   `json:"auto"` // round-robin auto-assign
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	var updated *domain.Case
	var err error
	if req.Auto || req.AssigneeID == "" {
		assignedBy := req.AssignedBy
		if assignedBy == "" {
			assignedBy = r.Header.Get("X-User-ID")
		}
		updated, err = h.svc.AutoAssign(r.Context(), caseID, assignedBy)
	} else {
		updated, err = h.svc.AssignCase(r.Context(), caseID, req.AssigneeID, req.AssignedBy)
	}
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------------------
// POST /cases/:id/evidence
// ---------------------------------------------------------------------------

func (h *Handler) AddEvidence(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/evidence")
	caseID := pathParam(path, "/cases/")
	if caseID == "" {
		writeError(w, http.StatusBadRequest, "case_id required")
		return
	}
	var req struct {
		UploadedBy   string `json:"uploaded_by"`
		FileName     string `json:"file_name"`
		FileSize     int64  `json:"file_size"`
		ContentType  string `json:"content_type"`
		EvidenceType string `json:"evidence_type"`
		Notes        string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.FileName == "" {
		writeError(w, http.StatusBadRequest, "file_name is required")
		return
	}
	if req.ContentType == "" {
		req.ContentType = "application/octet-stream"
	}
	if req.EvidenceType == "" {
		req.EvidenceType = "OTHER"
	}
	if req.UploadedBy == "" {
		req.UploadedBy = r.Header.Get("X-User-ID")
	}

	e, putURL, getURL, err := h.svc.AddEvidence(r.Context(), &service.AddEvidenceInput{
		CaseID:       caseID,
		UploadedBy:   req.UploadedBy,
		FileName:     req.FileName,
		FileSize:     req.FileSize,
		ContentType:  req.ContentType,
		EvidenceType: domain.EvidenceType(req.EvidenceType),
		Notes:        req.Notes,
	})
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"evidence":      e,
		"upload_url":    putURL,
		"presigned_url": getURL,
	})
}

// ---------------------------------------------------------------------------
// GET /cases/:id/evidence
// ---------------------------------------------------------------------------

func (h *Handler) GetEvidence(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/evidence")
	caseID := pathParam(path, "/cases/")
	evidenceID := r.URL.Query().Get("evidence_id")
	evs, urls, err := h.svc.GetEvidence(r.Context(), caseID, evidenceID)
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	type item struct {
		Evidence     *domain.Evidence `json:"evidence"`
		PresignedURL string           `json:"presigned_url"`
	}
	result := make([]item, len(evs))
	for i, e := range evs {
		u := ""
		if i < len(urls) {
			u = urls[i]
		}
		result[i] = item{Evidence: e, PresignedURL: u}
	}
	writeJSON(w, http.StatusOK, map[string]any{"evidence": result})
}

// ---------------------------------------------------------------------------
// DELETE /cases/:id/evidence/:evid
// ---------------------------------------------------------------------------

func (h *Handler) DeleteEvidence(w http.ResponseWriter, r *http.Request) {
	// Path: /cases/<caseID>/evidence/<evidenceID>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/cases/"), "/")
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "path: /cases/:id/evidence/:evidence_id")
		return
	}
	caseID := parts[0]
	evidenceID := parts[2]
	deletedBy := r.Header.Get("X-User-ID")
	if err := h.svc.DeleteEvidence(r.Context(), caseID, evidenceID, deletedBy); err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ---------------------------------------------------------------------------
// POST /cases/:id/sar
// ---------------------------------------------------------------------------

func (h *Handler) GenerateSAR(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/sar")
	caseID := pathParam(path, "/cases/")
	if caseID == "" {
		writeError(w, http.StatusBadRequest, "case_id required")
		return
	}
	var req struct {
		GeneratedBy string `json:"generated_by"`
		Notes       string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.GeneratedBy == "" {
		req.GeneratedBy = r.Header.Get("X-User-ID")
	}
	s3Key, downloadURL, err := h.svc.GenerateSAR(r.Context(), caseID, req.GeneratedBy, req.Notes)
	if err != nil {
		writeError(w, httpCode(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"case_id":      caseID,
		"s3_key":       s3Key,
		"download_url": downloadURL,
	})
}

// ---------------------------------------------------------------------------
// GET /cases/stats
// ---------------------------------------------------------------------------

func (h *Handler) GetCaseStats(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	stats, err := h.svc.GetCaseStats(r.Context(), period)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// ---------------------------------------------------------------------------
// GET /cases/workload
// ---------------------------------------------------------------------------

func (h *Handler) GetWorkload(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["investigator_id"]
	workloads, err := h.svc.GetInvestigatorWorkload(r.Context(), ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": workloads})
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

func intQ(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return n
	}
	return def
}

func httpCode(err error) int {
	var ce *domain.CaseError
	if !errors.As(err, &ce) {
		return http.StatusInternalServerError
	}
	switch ce.Code {
	case "CASE_NOT_FOUND", "EVIDENCE_NOT_FOUND":
		return http.StatusNotFound
	case "DUPLICATE_CASE":
		return http.StatusConflict
	case "INVALID_TRANSITION", "SAR_EXISTS":
		return http.StatusUnprocessableEntity
	case "INVALID_CASE", "NO_INVESTIGATORS":
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
