package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	"github.com/fraud-detection/blockchain-service/internal/domain"
	"github.com/fraud-detection/blockchain-service/internal/fabric"
)

type Service struct {
	cfg     appconfig.Config
	gateway fabric.Gateway

	// receiptMu serializes receipt anchoring: the chaincode increments a per-org
	// sequence counter in world state, so concurrent submissions from this org
	// would MVCC-conflict on the counter key.
	receiptMu sync.Mutex
}

func New(cfg appconfig.Config, gateway fabric.Gateway) *Service {
	return &Service{cfg: cfg, gateway: gateway}
}

// pseudonym maps a raw customer identifier to the on-chain pseudonym used on the
// alert- and audit-channels. Applied on both writes and reads so callers keep
// using real customer IDs while the ledger only ever sees pseudonyms.
func (s *Service) pseudonym(customerID string) string {
	return PseudonymizeCustomerID(s.cfg.CustomerHMACKey, customerID)
}

func (s *Service) RegisterKYC(ctx context.Context, req domain.RegisterKYCRequest) (domain.TransactionResponse, error) {
	if strings.TrimSpace(req.CustomerID) == "" || strings.TrimSpace(req.IdentityHash) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("customer_id and identity_hash are required")
	}

	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.KYCChannel, s.cfg.KYCChaincode, "RegisterCustomer", [][]byte{
		[]byte(req.CustomerID),
		[]byte(req.IdentityHash),
		[]byte(req.KYCStatus),
		[]byte(req.RiskLevel),
		[]byte(req.VerifierID),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) UpdateKYCStatus(ctx context.Context, req domain.UpdateKYCStatusRequest) (domain.TransactionResponse, error) {
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.KYCChannel, s.cfg.KYCChaincode, "UpdateKYCStatus", [][]byte{
		[]byte(req.CustomerID),
		[]byte(req.KYCStatus),
		[]byte(req.RiskLevel),
		[]byte(req.Reason),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) GetKYCRecord(ctx context.Context, customerID string) (domain.TransactionResponse, error) {
	payload, err := s.gateway.Query(ctx, s.cfg.KYCChannel, s.cfg.KYCChaincode, "GetKYCRecord", [][]byte{[]byte(customerID)})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	// Fabric queries don't produce a tx ID; surface the record's last-write txId instead.
	txID := extractPayloadTxID(payload)
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) CreateAlert(ctx context.Context, req domain.CreateAlertRequest) (domain.TransactionResponse, error) {
	// The alert-channel ledger is shared with the partner bank; anchor the
	// customer pseudonym, never the bank-internal identifier.
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "CreateAlert", [][]byte{
		[]byte(req.AlertID),
		[]byte(s.pseudonym(req.CustomerID)),
		[]byte(req.TxHash),
		[]byte(strconv.FormatFloat(req.FraudProb, 'f', -1, 64)),
		[]byte(strconv.FormatFloat(req.RiskScore, 'f', -1, 64)),
		[]byte(req.ModelVersion),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) UpdateAlertStatus(ctx context.Context, req domain.UpdateAlertStatusRequest) (domain.TransactionResponse, error) {
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "UpdateAlertStatus", [][]byte{
		[]byte(req.AlertID),
		[]byte(req.Status),
		[]byte(req.InvestigatorID),
		[]byte(req.Notes),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) RecordInvestigatorAction(ctx context.Context, req domain.InvestigatorActionRequest) (domain.TransactionResponse, error) {
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "RecordInvestigatorAction", [][]byte{
		[]byte(req.ActionID),
		[]byte(req.InvestigatorID),
		[]byte(req.CaseID),
		[]byte(req.Action),
		[]byte(req.Evidence),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

func (s *Service) RecordModelPrediction(ctx context.Context, req domain.ModelPredictionRequest) (domain.TransactionResponse, error) {
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "RecordModelPrediction", [][]byte{
		[]byte(req.PredictionID),
		[]byte(req.ModelVersion),
		[]byte(req.Features),
		[]byte(req.Prediction),
		[]byte(req.ShapValues),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

// receiptDetails mirrors the private payload expected by the audit-contract in
// transient key "receipt_details". It is stored only in the
// auditTransactionDetails Private Data Collection (issuing bank + regulator);
// the shared ledger carries only its SHA-256 digest.
type receiptDetails struct {
	CustomerID   string  `json:"customerId"`
	AmountUSD    float64 `json:"amountUsd"`
	CurrencyCode string  `json:"currencyCode"`
	Channel      string  `json:"channel"`
	CountryCode  string  `json:"countryCode"`
}

// receiptMaxAttempts bounds retries of receipt anchoring on sequence-counter
// MVCC conflicts (e.g. a receipt from another service instance of the same org
// committing between endorsement and validation).
const receiptMaxAttempts = 3

// RecordTransactionReceipt writes a TRANSACTION_PROCESSED audit record to the
// audit-channel for every ML-scored transaction (fraudulent and non-fraudulent).
// This creates an immutable, tamper-evident proof that the transaction was seen
// and scored, closing the fabrication gap in the compliance audit trail.
//
// The public record carries fraud metadata plus a chaincode-assigned per-org
// sequence number (gap-free by construction — the regulator reconciles the latest
// sequence against the bank's reported volume to prove completeness). Business
// details (customer pseudonym, amount, corridor) travel in the transient map and
// land only in the bank+regulator Private Data Collection.
func (s *Service) RecordTransactionReceipt(ctx context.Context, req domain.TransactionReceiptRequest) (domain.TransactionResponse, error) {
	if strings.TrimSpace(req.TxHash) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("tx_hash is required")
	}
	if strings.TrimSpace(req.CustomerID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("customer_id is required")
	}

	recordID := req.TxHash // txHash as recordID gives natural idempotency

	details, err := json.Marshal(receiptDetails{
		CustomerID:   s.pseudonym(req.CustomerID),
		AmountUSD:    req.AmountUSD,
		CurrencyCode: req.CurrencyCode,
		Channel:      req.Channel,
		CountryCode:  req.CountryCode,
	})
	if err != nil {
		return domain.TransactionResponse{}, fmt.Errorf("marshal receipt details: %w", err)
	}

	args := [][]byte{
		[]byte(recordID),
		[]byte(req.TxHash),
		[]byte(req.ProcessedAt),
		[]byte(strconv.FormatFloat(req.FraudProbability, 'f', -1, 64)),
		[]byte(req.RiskLevel),
		[]byte(strconv.FormatBool(req.AlertFired)),
		[]byte(req.AlertID),
		[]byte(req.ModelVersion),
		[]byte(req.PredictionID),
	}
	transient := map[string][]byte{"receipt_details": details}

	s.receiptMu.Lock()
	defer s.receiptMu.Unlock()

	var lastErr error
	for attempt := 1; attempt <= receiptMaxAttempts; attempt++ {
		txID, payload, err := s.gateway.InvokeWithTransient(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode,
			"RecordTransactionProcessed", args, transient, s.cfg.AuditPrivateOrgs)
		if err == nil {
			return newTransactionResponse(txID, payload), nil
		}
		lastErr = err
		if !isSequenceConflict(err) {
			return domain.TransactionResponse{}, err
		}
	}
	return domain.TransactionResponse{}, fmt.Errorf("anchor receipt after %d attempts: %w", receiptMaxAttempts, lastErr)
}

// isSequenceConflict reports whether an invoke failed on a read-write conflict
// over the per-org sequence counter (Fabric validation code 11/12), which is
// safe to retry.
func isSequenceConflict(err error) bool {
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "MVCC_READ_CONFLICT") ||
		strings.Contains(msg, "PHANTOM_READ_CONFLICT") ||
		strings.Contains(msg, "CODE 11") ||
		strings.Contains(msg, "CODE 12")
}

// RecordSARFiled writes a SAR_FILED audit record to the audit-channel when a SAR
// document is generated. The sarHash anchors the document content on-chain so that
// regulators can independently verify the PDF has not been modified after filing.
func (s *Service) RecordSARFiled(ctx context.Context, req domain.SARFiledRequest) (domain.TransactionResponse, error) {
	if strings.TrimSpace(req.CaseID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("case_id is required")
	}
	if strings.TrimSpace(req.SARHash) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("sar_hash is required")
	}
	if strings.TrimSpace(req.GeneratedBy) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("generated_by is required")
	}

	// recordID = caseID + "-sar" gives natural idempotency: one SAR per case.
	recordID := req.CaseID + "-sar"
	if strings.TrimSpace(req.RecordID) != "" {
		recordID = req.RecordID
	}

	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode,
		"RecordSARFiled", [][]byte{
			[]byte(recordID),
			[]byte(req.CaseID),
			[]byte(req.SARHash),
			[]byte(req.S3Key),
			[]byte(req.FiledAt),
			[]byte(req.GeneratedBy),
		})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
}

// ---------------------------------------------------------------------------
// KYC queries
// ---------------------------------------------------------------------------

func (s *Service) GetKYCHistory(ctx context.Context, customerID string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(customerID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("customer_id is required")
	}
	payload, err := s.gateway.Query(ctx, s.cfg.KYCChannel, s.cfg.KYCChaincode, "GetKYCHistory", [][]byte{[]byte(customerID)})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

func (s *Service) ListPendingKYC(ctx context.Context) (domain.TransactionResponse, error) {
	payload, err := s.gateway.Query(ctx, s.cfg.KYCChannel, s.cfg.KYCChaincode, "ListPendingKYC", nil)
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

// ---------------------------------------------------------------------------
// Alert queries
// ---------------------------------------------------------------------------

func (s *Service) GetAlertsByCustomer(ctx context.Context, customerID string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(customerID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("customer_id is required")
	}
	// Alerts are anchored under the customer pseudonym; translate the caller's
	// real customer ID the same way so the lookup matches.
	payload, err := s.gateway.Query(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "GetAlertsByCustomer", [][]byte{[]byte(s.pseudonym(customerID))})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

func (s *Service) GetAlertsByRiskLevel(ctx context.Context, level string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(level) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("risk level is required")
	}
	payload, err := s.gateway.Query(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "GetAlertsByRiskLevel", [][]byte{[]byte(level)})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

func (s *Service) GetAlertStats(ctx context.Context) (domain.TransactionResponse, error) {
	payload, err := s.gateway.Query(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "GetAlertStats", nil)
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

// ---------------------------------------------------------------------------
// Audit queries
// ---------------------------------------------------------------------------

func (s *Service) GetAuditTrail(ctx context.Context, entityID, entityType string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(entityID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("entity_id is required")
	}
	if strings.TrimSpace(entityType) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("entity_type is required")
	}
	payload, err := s.gateway.Query(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "GetAuditTrail", [][]byte{
		[]byte(entityID),
		[]byte(entityType),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

func (s *Service) GetComplianceReport(ctx context.Context, startDate, endDate string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(startDate) == "" || strings.TrimSpace(endDate) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("start_date and end_date are required")
	}
	payload, err := s.gateway.Query(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "GetComplianceReport", [][]byte{
		[]byte(startDate),
		[]byte(endDate),
	})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

// GetAuditSequenceStatus returns the latest TRANSACTION_PROCESSED sequence number
// per organization — the completeness checkpoint a regulator reconciles against
// each bank's reported transaction volume.
func (s *Service) GetAuditSequenceStatus(ctx context.Context) (domain.TransactionResponse, error) {
	payload, err := s.gateway.Query(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "GetSequenceStatus", nil)
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

// GetReceiptDetails returns the private half of a processing receipt (from the
// bank+regulator Private Data Collection) together with the chaincode's integrity
// verdict against the detailsHash anchored in the public record.
func (s *Service) GetReceiptDetails(ctx context.Context, recordID string) (domain.TransactionResponse, error) {
	if strings.TrimSpace(recordID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("record_id is required")
	}
	payload, err := s.gateway.Query(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "GetReceiptDetails", [][]byte{[]byte(recordID)})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse("", payload), nil
}

// GetAuditCompleteness reconciles this org's on-chain receipt count (the latest
// chaincode-assigned sequence, gap-free by construction) against an independently
// sourced expected transaction count. A shortfall is provable evidence that
// processed transactions were never anchored.
func (s *Service) GetAuditCompleteness(ctx context.Context, expectedCount uint64) (domain.CompletenessResponse, error) {
	payload, err := s.gateway.Query(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode, "GetSequenceStatus", nil)
	if err != nil {
		return domain.CompletenessResponse{}, err
	}

	var statuses []struct {
		MSPID          string `json:"mspId"`
		LatestSequence uint64 `json:"latestSequence"`
	}
	if err := json.Unmarshal(payload, &statuses); err != nil {
		return domain.CompletenessResponse{}, fmt.Errorf("decode sequence status: %w", err)
	}

	var anchored uint64
	for _, status := range statuses {
		if status.MSPID == s.cfg.MSPID {
			anchored = status.LatestSequence
			break
		}
	}

	resp := domain.CompletenessResponse{
		MSPID:            s.cfg.MSPID,
		AnchoredReceipts: anchored,
		ExpectedCount:    expectedCount,
		Complete:         anchored >= expectedCount,
	}
	if expectedCount > anchored {
		resp.MissingReceipts = expectedCount - anchored
	}
	return resp, nil
}

func (s *Service) Health(ctx context.Context) domain.HealthResponse {
	details := s.gateway.Health(ctx)
	status := "serving"
	for _, value := range details {
		if strings.Contains(strings.ToLower(value), "error") || strings.Contains(strings.ToLower(value), "failed") {
			status = "degraded"
			break
		}
	}
	return domain.HealthResponse{Status: status, Details: details}
}

func newTransactionResponse(txID string, payload []byte) domain.TransactionResponse {
	resp := domain.TransactionResponse{TransactionID: txID}
	if len(payload) > 0 && json.Valid(payload) {
		resp.Payload = append(resp.Payload[:0], payload...)
	}
	return resp
}

// extractPayloadTxID pulls the "txId" field from a JSON payload returned by a
// chaincode query. Fabric query calls don't produce a Fabric transaction ID, so
// the chaincode embeds the last-write tx ID in the record itself.
func extractPayloadTxID(payload []byte) string {
	var record struct {
		TxID string `json:"txId"`
	}
	if err := json.Unmarshal(payload, &record); err == nil {
		return record.TxID
	}
	return ""
}
