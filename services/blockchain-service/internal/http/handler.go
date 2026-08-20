package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fraud-detection/blockchain-service/internal/domain"
	"github.com/fraud-detection/blockchain-service/internal/service"
	"github.com/rs/zerolog"
)

type Handler struct {
	svc *service.Service
	log zerolog.Logger
}

func NewHandler(svc *service.Service, log zerolog.Logger) *Handler {
	return &Handler{svc: svc, log: log.With().Str("component", "http_handler").Logger()}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.handleHealth)

	// KYC writes
	mux.HandleFunc("/internal/v1/kyc/register", h.handleRegisterKYC)
	mux.HandleFunc("/internal/v1/kyc/status", h.handleUpdateKYCStatus)

	// KYC reads
	mux.HandleFunc("/internal/v1/kyc/record/", h.handleGetKYCRecord)
	mux.HandleFunc("/internal/v1/kyc/history/", h.handleGetKYCHistory)
	mux.HandleFunc("/internal/v1/kyc/pending", h.handleListPendingKYC)

	// Alert writes
	mux.HandleFunc("/internal/v1/alerts/create", h.handleCreateAlert)
	mux.HandleFunc("/internal/v1/alerts/status", h.handleUpdateAlertStatus)

	// Alert reads
	mux.HandleFunc("/internal/v1/alerts/customer/", h.handleGetAlertsByCustomer)
	mux.HandleFunc("/internal/v1/alerts/risk/", h.handleGetAlertsByRiskLevel)
	mux.HandleFunc("/internal/v1/alerts/stats", h.handleGetAlertStats)

	// Audit writes
	mux.HandleFunc("/internal/v1/audit/investigator-action", h.handleInvestigatorAction)
	mux.HandleFunc("/internal/v1/audit/model-prediction", h.handleModelPrediction)
	mux.HandleFunc("/internal/v1/audit/transaction-receipt", h.handleTransactionReceipt)
	mux.HandleFunc("/internal/v1/audit/sar-filed", h.handleSARFiled)

	// Audit reads
	mux.HandleFunc("/internal/v1/audit/trail", h.handleGetAuditTrail)
	mux.HandleFunc("/internal/v1/audit/compliance", h.handleGetComplianceReport)
	mux.HandleFunc("/internal/v1/audit/sequence", h.handleGetAuditSequence)
	mux.HandleFunc("/internal/v1/audit/completeness", h.handleGetAuditCompleteness)
	mux.HandleFunc("/internal/v1/audit/receipt-details/", h.handleGetReceiptDetails)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, h.svc.Health(r.Context()))
}

func (h *Handler) handleRegisterKYC(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.RegisterKYCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.RegisterKYC(ctx, req)
	})
}

func (h *Handler) handleUpdateKYCStatus(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.UpdateKYCStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.UpdateKYCStatus(ctx, req)
	})
}

func (h *Handler) handleGetKYCRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	customerID := strings.TrimPrefix(r.URL.Path, "/internal/v1/kyc/record/")
	resp, err := h.svc.GetKYCRecord(r.Context(), customerID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleCreateAlert(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.CreateAlertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.CreateAlert(ctx, req)
	})
}

func (h *Handler) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.UpdateAlertStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.UpdateAlertStatus(ctx, req)
	})
}

func (h *Handler) handleInvestigatorAction(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.InvestigatorActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.RecordInvestigatorAction(ctx, req)
	})
}

func (h *Handler) handleModelPrediction(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.ModelPredictionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.RecordModelPrediction(ctx, req)
	})
}

func (h *Handler) handleTransactionReceipt(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.TransactionReceiptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.RecordTransactionReceipt(ctx, req)
	})
}

func (h *Handler) handleSARFiled(w http.ResponseWriter, r *http.Request) {
	h.handleJSON(w, r, func(ctx context.Context) (interface{}, error) {
		var req domain.SARFiledRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return h.svc.RecordSARFiled(ctx, req)
	})
}

// ---------------------------------------------------------------------------
// KYC query handlers
// ---------------------------------------------------------------------------

func (h *Handler) handleGetKYCHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	customerID := strings.TrimPrefix(r.URL.Path, "/internal/v1/kyc/history/")
	resp, err := h.svc.GetKYCHistory(r.Context(), customerID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleListPendingKYC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := h.svc.ListPendingKYC(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Alert query handlers
// ---------------------------------------------------------------------------

func (h *Handler) handleGetAlertsByCustomer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	customerID := strings.TrimPrefix(r.URL.Path, "/internal/v1/alerts/customer/")
	resp, err := h.svc.GetAlertsByCustomer(r.Context(), customerID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleGetAlertsByRiskLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	level := strings.TrimPrefix(r.URL.Path, "/internal/v1/alerts/risk/")
	resp, err := h.svc.GetAlertsByRiskLevel(r.Context(), level)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleGetAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := h.svc.GetAlertStats(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// Audit query handlers
// ---------------------------------------------------------------------------

func (h *Handler) handleGetAuditTrail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	entityID := strings.TrimSpace(q.Get("entity_id"))
	entityType := strings.TrimSpace(q.Get("entity_type"))
	if entityID == "" || entityType == "" {
		h.writeError(w, fmt.Errorf("entity_id and entity_type query params are required"))
		return
	}
	resp, err := h.svc.GetAuditTrail(r.Context(), entityID, entityType)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleGetComplianceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	startDate := strings.TrimSpace(q.Get("start_date"))
	endDate := strings.TrimSpace(q.Get("end_date"))
	if startDate == "" || endDate == "" {
		h.writeError(w, fmt.Errorf("start_date and end_date query params are required (RFC3339)"))
		return
	}
	resp, err := h.svc.GetComplianceReport(r.Context(), startDate, endDate)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetAuditSequence returns the latest TRANSACTION_PROCESSED sequence number
// per organization — the regulator's audit-completeness checkpoint.
func (h *Handler) handleGetAuditSequence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := h.svc.GetAuditSequenceStatus(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetAuditCompleteness reconciles this org's anchored receipt count against
// an expected transaction count supplied by the caller (e.g. the bank's MongoDB
// count, or the regulator's reported-volume figure).
func (h *Handler) handleGetAuditCompleteness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("expected_count"))
	if raw == "" {
		h.writeError(w, fmt.Errorf("expected_count query param is required"))
		return
	}
	expected, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		h.writeError(w, fmt.Errorf("expected_count must be a non-negative integer"))
		return
	}
	resp, err := h.svc.GetAuditCompleteness(r.Context(), expected)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetReceiptDetails returns the private half of a processing receipt from
// the bank+regulator Private Data Collection, hash-verified by the chaincode.
func (h *Handler) handleGetReceiptDetails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	recordID := strings.TrimPrefix(r.URL.Path, "/internal/v1/audit/receipt-details/")
	resp, err := h.svc.GetReceiptDetails(r.Context(), recordID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleJSON(w http.ResponseWriter, r *http.Request, fn func(context.Context) (interface{}, error)) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := fn(ctx)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	h.log.Error().Err(err).Msg("request failed")
	h.writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
}

// statusForError maps a service/chaincode error to the most appropriate HTTP
// status. A missing ledger record is a 404 (not a 400 "bad request"); an
// unreachable Fabric network is a 503. Everything else stays a generic 400.
func statusForError(err error) int {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"), strings.Contains(msg, "does not exist"):
		return http.StatusNotFound
	case strings.Contains(msg, "unavailable"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no connection"),
		strings.Contains(msg, "deadline exceeded"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}
