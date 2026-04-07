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
	return newTransactionResponse("", payload), nil
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
