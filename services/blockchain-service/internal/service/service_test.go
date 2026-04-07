package service

import (
	"context"
	"fmt"
	"testing"

	appconfig "github.com/fraud-detection/blockchain-service/internal/config"
	"github.com/fraud-detection/blockchain-service/internal/domain"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock gateway
// ---------------------------------------------------------------------------

type mockGateway struct {
	invokeFn func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error)
	queryFn  func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error)
}

func (m *mockGateway) Invoke(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
	return m.invokeFn(ctx, channelName, chaincodeName, function, args)
}

func (m *mockGateway) Query(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
	return m.queryFn(ctx, channelName, chaincodeName, function, args)
}

func (m *mockGateway) StartEventListeners(ctx context.Context) error { return nil }
func (m *mockGateway) Health(ctx context.Context) map[string]string {
	return map[string]string{"kyc-channel": "connected"}
}
func (m *mockGateway) Close() {}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func testConfig() appconfig.Config {
	return appconfig.Config{
		KYCChannel:     "kyc-channel",
		AlertChannel:   "alert-channel",
		AuditChannel:   "audit-channel",
		KYCChaincode:   "kyc-contract",
		AlertChaincode: "alert-contract",
		AuditChaincode: "audit-contract",
	}
}

// ---------------------------------------------------------------------------
// KYC write tests
// ---------------------------------------------------------------------------

func TestRegisterKYC(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "kyc-channel", channelName)
			require.Equal(t, "kyc-contract", chaincodeName)
			require.Equal(t, "RegisterCustomer", function)
			require.Len(t, args, 5)
			return "tx-1", []byte(`{"customerID":"customer-1"}`), nil
		},
	})

	resp, err := svc.RegisterKYC(context.Background(), domain.RegisterKYCRequest{
		CustomerID:   "customer-1",
		IdentityHash: "hash-1234567890abcdef",
		KYCStatus:    "PENDING",
		RiskLevel:    "LOW",
		VerifierID:   "verifier-1",
	})
	require.NoError(t, err)
	require.Equal(t, "tx-1", resp.TransactionID)
	require.JSONEq(t, `{"customerID":"customer-1"}`, string(resp.Payload))
}

func TestRegisterKYC_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.RegisterKYC(context.Background(), domain.RegisterKYCRequest{
		CustomerID:   "",
		IdentityHash: "hash-1234567890abcdef",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "customer_id and identity_hash are required")
}

func TestUpdateKYCStatus(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "UpdateKYCStatus", function)
			require.Equal(t, "customer-1", string(args[0]))
			require.Equal(t, "APPROVED", string(args[1]))
			return "tx-2", []byte(`{"kycStatus":"APPROVED"}`), nil
		},
	})

	resp, err := svc.UpdateKYCStatus(context.Background(), domain.UpdateKYCStatusRequest{
		CustomerID: "customer-1",
		KYCStatus:  "APPROVED",
		Reason:     "manual review",
	})
	require.NoError(t, err)
	require.Equal(t, "tx-2", resp.TransactionID)
}

// ---------------------------------------------------------------------------
// KYC query tests
// ---------------------------------------------------------------------------

func TestGetKYCRecord(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetKYCRecord", function)
			require.Equal(t, "customer-1", string(args[0]))
			return []byte(`{"customerID":"customer-1","kycStatus":"PENDING"}`), nil
		},
	})

	resp, err := svc.GetKYCRecord(context.Background(), "customer-1")
	require.NoError(t, err)
	require.JSONEq(t, `{"customerID":"customer-1","kycStatus":"PENDING"}`, string(resp.Payload))
}

func TestGetKYCHistory(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetKYCHistory", function)
			require.Equal(t, "customer-1", string(args[0]))
			return []byte(`[{"kycStatus":"PENDING"},{"kycStatus":"APPROVED"}]`), nil
		},
	})

	resp, err := svc.GetKYCHistory(context.Background(), "customer-1")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

func TestGetKYCHistory_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.GetKYCHistory(context.Background(), "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "customer_id is required")
}

func TestListPendingKYC(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "ListPendingKYC", function)
			require.Nil(t, args)
			return []byte(`[{"customerID":"c1","kycStatus":"PENDING"}]`), nil
		},
	})

	resp, err := svc.ListPendingKYC(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

// ---------------------------------------------------------------------------
// Alert write tests
// ---------------------------------------------------------------------------

func TestCreateAlert(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "alert-channel", channelName)
			require.Equal(t, "CreateAlert", function)
			require.Len(t, args, 6)
			require.Equal(t, "alert-1", string(args[0]))
			return "tx-3", []byte(`{"alertID":"alert-1","status":"OPEN"}`), nil
		},
	})

	resp, err := svc.CreateAlert(context.Background(), domain.CreateAlertRequest{
		AlertID:      "alert-1",
		CustomerID:   "customer-1",
		TxHash:       "txhash-abc",
		FraudProb:    0.92,
		RiskScore:    96.5,
		ModelVersion: "ensemble-v1",
	})
	require.NoError(t, err)
	require.Equal(t, "tx-3", resp.TransactionID)
}

func TestUpdateAlertStatus(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "UpdateAlertStatus", function)
			require.Equal(t, "alert-1", string(args[0]))
			require.Equal(t, "INVESTIGATING", string(args[1]))
			return "tx-4", []byte(`{"status":"INVESTIGATING"}`), nil
		},
	})

	resp, err := svc.UpdateAlertStatus(context.Background(), domain.UpdateAlertStatusRequest{
		AlertID:        "alert-1",
		Status:         "INVESTIGATING",
		InvestigatorID: "investigator-9",
		Notes:          "triaging",
	})
	require.NoError(t, err)
	require.Equal(t, "tx-4", resp.TransactionID)
}

// ---------------------------------------------------------------------------
// Alert query tests
// ---------------------------------------------------------------------------

func TestGetAlertsByCustomer(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetAlertsByCustomer", function)
			require.Equal(t, "customer-1", string(args[0]))
			return []byte(`[{"alertID":"alert-1"}]`), nil
		},
	})

	resp, err := svc.GetAlertsByCustomer(context.Background(), "customer-1")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

func TestGetAlertsByCustomer_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.GetAlertsByCustomer(context.Background(), "")
	require.Error(t, err)
}

func TestGetAlertsByRiskLevel(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetAlertsByRiskLevel", function)
			require.Equal(t, "CRITICAL", string(args[0]))
			return []byte(`[{"alertID":"alert-1","riskLevel":"CRITICAL"}]`), nil
		},
	})

	resp, err := svc.GetAlertsByRiskLevel(context.Background(), "CRITICAL")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

func TestGetAlertsByRiskLevel_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.GetAlertsByRiskLevel(context.Background(), "")
	require.Error(t, err)
}

func TestGetAlertStats(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetAlertStats", function)
			require.Nil(t, args)
			return []byte(`{"totalAlerts":5,"criticalAlerts":2}`), nil
		},
	})

	resp, err := svc.GetAlertStats(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

// ---------------------------------------------------------------------------
// Audit write tests
// ---------------------------------------------------------------------------

func TestRecordInvestigatorAction(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "audit-channel", channelName)
			require.Equal(t, "RecordInvestigatorAction", function)
			require.Len(t, args, 5)
			return "tx-5", []byte(`{"recordID":"action-1"}`), nil
		},
	})

	resp, err := svc.RecordInvestigatorAction(context.Background(), domain.InvestigatorActionRequest{
		ActionID:       "action-1",
		InvestigatorID: "investigator-1",
		CaseID:         "case-22",
		Action:         "REVIEWED",
		Evidence:       "s3://evidence/file.pdf",
	})
	require.NoError(t, err)
	require.Equal(t, "tx-5", resp.TransactionID)
}

func TestRecordModelPrediction(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			require.Equal(t, "RecordModelPrediction", function)
			require.Len(t, args, 5)
			return "tx-6", []byte(`{"recordID":"prediction-1"}`), nil
		},
	})

	resp, err := svc.RecordModelPrediction(context.Background(), domain.ModelPredictionRequest{
		PredictionID: "prediction-1",
		ModelVersion: "gnn-v4",
		Features:     `{"velocity_1h":4.2}`,
		Prediction:   "fraud",
		ShapValues:   `{"velocity_1h":0.17}`,
	})
	require.NoError(t, err)
	require.Equal(t, "tx-6", resp.TransactionID)
}

// ---------------------------------------------------------------------------
// Audit query tests
// ---------------------------------------------------------------------------

func TestGetAuditTrail(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetAuditTrail", function)
			require.Equal(t, "case-22", string(args[0]))
			require.Equal(t, "CASE", string(args[1]))
			return []byte(`[{"recordID":"action-1","entityType":"CASE"}]`), nil
		},
	})

	resp, err := svc.GetAuditTrail(context.Background(), "case-22", "CASE")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

func TestGetAuditTrail_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.GetAuditTrail(context.Background(), "", "CASE")
	require.Error(t, err)
	require.Contains(t, err.Error(), "entity_id is required")

	_, err = svc.GetAuditTrail(context.Background(), "case-1", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "entity_type is required")
}

func TestGetComplianceReport(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		queryFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) ([]byte, error) {
			require.Equal(t, "GetComplianceReport", function)
			require.Equal(t, "2026-04-01T00:00:00Z", string(args[0]))
			require.Equal(t, "2026-04-02T00:00:00Z", string(args[1]))
			return []byte(`{"totalEvents":5,"investigatorActions":3,"modelPredictions":2}`), nil
		},
	})

	resp, err := svc.GetComplianceReport(context.Background(), "2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Payload)
}

func TestGetComplianceReport_ValidationError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	_, err := svc.GetComplianceReport(context.Background(), "", "2026-04-02T00:00:00Z")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Health check test
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	svc := New(testConfig(), &mockGateway{})
	health := svc.Health(context.Background())
	require.Equal(t, "serving", health.Status)
	require.Contains(t, health.Details, "kyc-channel")
}

// ---------------------------------------------------------------------------
// Gateway error propagation test
// ---------------------------------------------------------------------------

func TestRegisterKYC_GatewayError(t *testing.T) {
	svc := New(testConfig(), &mockGateway{
		invokeFn: func(ctx context.Context, channelName, chaincodeName, function string, args [][]byte) (string, []byte, error) {
			return "", nil, fmt.Errorf("peer connection failed")
		},
	})

	_, err := svc.RegisterKYC(context.Background(), domain.RegisterKYCRequest{
		CustomerID:   "customer-1",
		IdentityHash: "hash-1234567890abcdef",
		KYCStatus:    "PENDING",
		RiskLevel:    "LOW",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "peer connection failed")
}
