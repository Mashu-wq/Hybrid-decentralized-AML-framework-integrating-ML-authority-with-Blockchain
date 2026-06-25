package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	"github.com/fraud-detection/blockchain-service/internal/domain"
	"github.com/fraud-detection/blockchain-service/internal/fabric"
)

type Service struct {
	cfg     appconfig.Config
	gateway fabric.Gateway
}

func New(cfg appconfig.Config, gateway fabric.Gateway) *Service {
	return &Service{cfg: cfg, gateway: gateway}
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
	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "CreateAlert", [][]byte{
		[]byte(req.AlertID),
		[]byte(req.CustomerID),
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

// RecordTransactionReceipt writes a TRANSACTION_PROCESSED audit record to the
// audit-channel for every ML-scored transaction (fraudulent and non-fraudulent).
// This creates an immutable, tamper-evident proof that the transaction was seen
// and scored, closing the fabrication gap in the compliance audit trail.
func (s *Service) RecordTransactionReceipt(ctx context.Context, req domain.TransactionReceiptRequest) (domain.TransactionResponse, error) {
	if strings.TrimSpace(req.TxHash) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("tx_hash is required")
	}
	if strings.TrimSpace(req.CustomerID) == "" {
		return domain.TransactionResponse{}, fmt.Errorf("customer_id is required")
	}

	recordID := req.TxHash // txHash as recordID gives natural idempotency

	txID, payload, err := s.gateway.Invoke(ctx, s.cfg.AuditChannel, s.cfg.AuditChaincode,
		"RecordTransactionProcessed", [][]byte{
			[]byte(recordID),
			[]byte(req.TxHash),
			[]byte(req.CustomerID),
			[]byte(strconv.FormatFloat(req.AmountUSD, 'f', -1, 64)),
			[]byte(req.CurrencyCode),
			[]byte(req.Channel),
			[]byte(req.CountryCode),
			[]byte(req.ProcessedAt),
			[]byte(strconv.FormatFloat(req.FraudProbability, 'f', -1, 64)),
			[]byte(req.RiskLevel),
			[]byte(strconv.FormatBool(req.AlertFired)),
			[]byte(req.AlertID),
			[]byte(req.ModelVersion),
			[]byte(req.PredictionID),
		})
	if err != nil {
		return domain.TransactionResponse{}, err
	}
	return newTransactionResponse(txID, payload), nil
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
	payload, err := s.gateway.Query(ctx, s.cfg.AlertChannel, s.cfg.AlertChaincode, "GetAlertsByCustomer", [][]byte{[]byte(customerID)})
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
