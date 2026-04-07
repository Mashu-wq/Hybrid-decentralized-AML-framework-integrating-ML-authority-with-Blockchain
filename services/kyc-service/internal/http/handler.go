// Package http — KYC HTTP handlers.
// Delegates all business logic to KYCService; maps domain errors to HTTP status codes.
package http

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/fraud-detection/kyc-service/internal/domain"
	"github.com/fraud-detection/kyc-service/internal/service"
	"github.com/fraud-detection/kyc-service/internal/storage"
	"github.com/rs/zerolog"
)

// KYCHTTPHandler holds all HTTP route handlers for the KYC service.
type KYCHTTPHandler struct {
	kycSvc *service.KYCService
	store  storage.DocumentStore
	log    zerolog.Logger
}

// NewKYCHTTPHandler constructs a KYCHTTPHandler.
func NewKYCHTTPHandler(kycSvc *service.KYCService, store storage.DocumentStore, log zerolog.Logger) *KYCHTTPHandler {
	return &KYCHTTPHandler{kycSvc: kycSvc, store: store, log: log.With().Str("component", "http_handler").Logger()}
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

type registerCustomerRequest struct {
	// PII — never log these fields
	FullName       string `json:"full_name"`
	DateOfBirth    string `json:"date_of_birth"`
	AddressLine1   string `json:"address_line1"`
	AddressLine2   string `json:"address_line2"`
	Email          string `json:"email"`
	PhoneNumber    string `json:"phone_number"`
	DocumentNumber string `json:"document_number"`
	ExpiryDate     string `json:"expiry_date"`

	// Document metadata
	DocumentType   string `json:"document_type"`
	CountryOfIssue string `json:"country_of_issue"`

	// Profile
	Nationality           string  `json:"nationality"`
	City                  string  `json:"city"`
	CountryCode           string  `json:"country_code"`
	PostalCode            string  `json:"postal_code"`
	Occupation            string  `json:"occupation"`
	Employer              string  `json:"employer"`
	SourceOfFunds         string  `json:"source_of_funds"`
	ExpectedMonthlyVolume float64 `json:"expected_monthly_volume"`
}

type submitDocumentRequest struct {
	DocumentType string `json:"document_type"`
	S3Key        string `json:"s3_key"`
	ContentType  string `json:"content_type"`
	IsFront      bool   `json:"is_front"`
}

type verifyFaceRequest struct {
	SelfieS3Key   string `json:"selfie_s3_key"`
	DocumentS3Key string `json:"document_s3_key"`
	CheckLiveness bool   `json:"check_liveness"`
}

type updateKYCStatusRequest struct {
	Status     string `json:"status"`
	RiskLevel  string `json:"risk_level"`
	VerifierID string `json:"verifier_id"`
	Reason     string `json:"reason"`
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// RegisterCustomer handles POST /api/v1/kyc/customers.
func (h *KYCHTTPHandler) RegisterCustomer(w http.ResponseWriter, r *http.Request) {
	var req registerCustomerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if req.FullName == "" || req.Email == "" || req.DocumentType == "" || req.CountryCode == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "full_name, email, document_type, and country_code are required")
		return
	}

	in := &service.RegisterCustomerInput{
		FullName:              req.FullName,
		DateOfBirth:           req.DateOfBirth,
		AddressLine1:          req.AddressLine1,
		AddressLine2:          req.AddressLine2,
		Email:                 req.Email,
		PhoneNumber:           req.PhoneNumber,
		DocumentNumber:        req.DocumentNumber,
		ExpiryDate:            req.ExpiryDate,
		DocumentType:          req.DocumentType,
		CountryOfIssue:        req.CountryOfIssue,
		Nationality:           req.Nationality,
		City:                  req.City,
		CountryCode:           req.CountryCode,
		PostalCode:            req.PostalCode,
		Occupation:            req.Occupation,
		Employer:              req.Employer,
		SourceOfFunds:         req.SourceOfFunds,
		ExpectedMonthlyVolume: req.ExpectedMonthlyVolume,
	}

	customer, err := h.kycSvc.RegisterCustomer(r.Context(), in)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"customer_id":   customer.ID,
		"identity_hash": customer.IdentityHash,
		"kyc_status":    string(customer.KYCStatus),
		"created_at":    customer.CreatedAt,
	})
}

// GetKYCRecord handles GET /api/v1/kyc/customers/{id}.
func (h *KYCHTTPHandler) GetKYCRecord(w http.ResponseWriter, r *http.Request) {
	customerID := r.PathValue("id")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "customer id is required")
		return
	}

	customer, err := h.kycSvc.GetKYCRecord(r.Context(), customerID)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, customer)
}

// ListCustomers handles GET /api/v1/kyc/customers.
func (h *KYCHTTPHandler) ListCustomers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	statusStr := q.Get("status")
	if statusStr == "" {
		statusStr = string(domain.KYCStatusPending)
	}
	countryCode := q.Get("country_code")

	limit := 20
	offset := 0
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	customers, total, err := h.kycSvc.ListByStatus(r.Context(), domain.KYCStatus(statusStr), countryCode, limit, offset)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"customers":   customers,
		"total_count": total,
		"limit":       limit,
		"offset":      offset,
	})
}

// UpdateKYCStatus handles PATCH /api/v1/kyc/customers/{id}/status.
func (h *KYCHTTPHandler) UpdateKYCStatus(w http.ResponseWriter, r *http.Request) {
	customerID := r.PathValue("id")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "customer id is required")
		return
	}

	var req updateKYCStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if req.Status == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "status is required")
		return
	}

	in := &service.UpdateKYCStatusInput{
		CustomerID: customerID,
		Status:     domain.KYCStatus(req.Status),
		RiskLevel:  domain.RiskLevel(req.RiskLevel),
		VerifierID: req.VerifierID,
		Reason:     req.Reason,
	}

	customer, err := h.kycSvc.UpdateKYCStatus(r.Context(), in)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"customer_id":      customer.ID,
		"kyc_status":       string(customer.KYCStatus),
		"risk_level":       string(customer.RiskLevel),
		"blockchain_tx_id": customer.BlockchainTxID,
		"updated_at":       customer.UpdatedAt,
	})
}

// SubmitDocument handles POST /api/v1/kyc/customers/{id}/documents.
func (h *KYCHTTPHandler) SubmitDocument(w http.ResponseWriter, r *http.Request) {
	customerID := r.PathValue("id")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "customer id is required")
		return
	}

	if isMultipartRequest(r) {
		h.submitMultipartDocument(w, r, customerID)
		return
	}

	var req submitDocumentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if req.S3Key == "" || req.DocumentType == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "s3_key and document_type are required")
		return
	}

	in := &service.SubmitDocumentInput{
		CustomerID:   customerID,
		DocumentType: req.DocumentType,
		S3Key:        req.S3Key,
		ContentType:  req.ContentType,
		IsFront:      req.IsFront,
	}

	doc, err := h.kycSvc.SubmitDocument(r.Context(), in)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"document_id":  doc.ID,
		"status":       doc.Status,
		"ocr_result":   doc.OCRResult,
		"completed_at": doc.UpdatedAt,
	})
}

func (h *KYCHTTPHandler) submitMultipartDocument(w http.ResponseWriter, r *http.Request, customerID string) {
	if h.store == nil {
		writeError(w, http.StatusNotImplemented, "DOCUMENT_UPLOAD_UNAVAILABLE", "multipart uploads are not configured")
		return
	}

	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_MULTIPART", err.Error())
		return
	}

	documentType := r.FormValue("document_type")
	if documentType == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "document_type is required")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "file is required")
		return
	}
	defer file.Close()

	storedKey, err := h.store.SaveUploadedDocument(r.Context(), customerID, header.Filename, file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "UPLOAD_FAILED", err.Error())
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = detectContentType(file)
	}

	in := &service.SubmitDocumentInput{
		CustomerID:   customerID,
		DocumentType: documentType,
		S3Key:        storedKey,
		ContentType:  contentType,
		IsFront:      strings.EqualFold(r.FormValue("is_front"), "true") || r.FormValue("is_front") == "1",
	}

	doc, err := h.kycSvc.SubmitDocument(r.Context(), in)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"document_id":  doc.ID,
		"status":       doc.Status,
		"stored_key":   storedKey,
		"ocr_result":   doc.OCRResult,
		"completed_at": doc.UpdatedAt,
	})
}

// VerifyFace handles POST /api/v1/kyc/customers/{id}/face-verify.
func (h *KYCHTTPHandler) VerifyFace(w http.ResponseWriter, r *http.Request) {
	customerID := r.PathValue("id")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "customer id is required")
		return
	}

	var req verifyFaceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if req.SelfieS3Key == "" || req.DocumentS3Key == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "selfie_s3_key and document_s3_key are required")
		return
	}

	in := &service.VerifyFaceInput{
		CustomerID:    customerID,
		SelfieS3Key:   req.SelfieS3Key,
		DocumentS3Key: req.DocumentS3Key,
		CheckLiveness: req.CheckLiveness,
	}

	result, err := h.kycSvc.VerifyFace(r.Context(), in)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"customer_id":     customerID,
		"face_match":      result.FaceMatch,
		"match_score":     result.MatchScore,
		"liveness_passed": result.LivenessPassed,
		"liveness_score":  result.LivenessScore,
		"model_version":   result.ModelVersion,
		"failure_reason":  result.FailureReason,
	})
}

// GetDecryptedPII handles GET /api/v1/kyc/customers/{id}/pii.
// IMPORTANT: The response body contains raw PII — never log it.
func (h *KYCHTTPHandler) GetDecryptedPII(w http.ResponseWriter, r *http.Request) {
	customerID := r.PathValue("id")
	if customerID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "customer id is required")
		return
	}

	reason := r.URL.Query().Get("reason")
	if reason == "" {
		writeError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "reason query parameter is required for PII access")
		return
	}

	// Actor ID should come from JWT claims in a production auth middleware.
	// For now, read from a header set by the auth interceptor.
	actorID := r.Header.Get("X-User-ID")

	// IMPORTANT: Do not log the result — it contains raw PII.
	result, err := h.kycSvc.GetDecryptedPII(r.Context(), customerID, actorID, reason)
	if err != nil {
		writeKYCError(w, err)
		return
	}

	// DO NOT LOG response body — all fields are PII.
	writeJSON(w, http.StatusOK, result)
}

// HealthCheck handles GET /health.
func (h *KYCHTTPHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "serving",
		"service": "kyc-service",
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// decodeJSON decodes the request body into dst.
func decodeJSON(r *http.Request, dst interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func isMultipartRequest(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "multipart/form-data"
}

func detectContentType(file io.ReadSeeker) string {
	if file == nil {
		return "application/octet-stream"
	}

	currentPos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return "application/octet-stream"
	}
	defer file.Seek(currentPos, io.SeekStart)

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "application/octet-stream"
	}

	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return "application/octet-stream"
	}

	return http.DetectContentType(header[:n])
}

// writeJSON serialises v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Header already written — can't change status code now.
		return
	}
}

// writeError writes a structured JSON error response.
func writeError(w http.ResponseWriter, httpCode int, code, message string) {
	writeJSON(w, httpCode, errorResponse{Code: code, Message: message})
}

// writeKYCError maps a domain KYCError to the appropriate HTTP status code.
func writeKYCError(w http.ResponseWriter, err error) {
	var kycErr *domain.KYCError
	if !errors.As(err, &kycErr) {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "an internal error occurred")
		return
	}

	switch kycErr.Code {
	case domain.ErrCustomerNotFound, domain.ErrDocumentNotFound:
		writeError(w, http.StatusNotFound, string(kycErr.Code), kycErr.Message)
	case domain.ErrCustomerAlreadyExists:
		writeError(w, http.StatusConflict, string(kycErr.Code), kycErr.Message)
	case domain.ErrInvalidStatus:
		writeError(w, http.StatusUnprocessableEntity, string(kycErr.Code), kycErr.Message)
	case domain.ErrPermissionDenied:
		writeError(w, http.StatusForbidden, string(kycErr.Code), kycErr.Message)
	default:
		writeError(w, http.StatusInternalServerError, string(kycErr.Code), kycErr.Message)
	}
}
