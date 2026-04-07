package domain

import "encoding/json"

type RegisterKYCRequest struct {
	CustomerID   string `json:"customer_id"`
	IdentityHash string `json:"identity_hash"`
	KYCStatus    string `json:"kyc_status"`
	RiskLevel    string `json:"risk_level"`
	VerifierID   string `json:"verifier_id,omitempty"`
}

type UpdateKYCStatusRequest struct {
	CustomerID string `json:"customer_id"`
	KYCStatus  string `json:"kyc_status"`
	Reason     string `json:"reason,omitempty"`
	VerifierID string `json:"verifier_id,omitempty"`
}

type CreateAlertRequest struct {
	AlertID      string  `json:"alert_id"`
	CustomerID   string  `json:"customer_id"`
	TxHash       string  `json:"tx_hash"`
	FraudProb    float64 `json:"fraud_probability"`
	RiskScore    float64 `json:"risk_score"`
	ModelVersion string  `json:"model_version"`
}

type UpdateAlertStatusRequest struct {
	AlertID        string `json:"alert_id"`
	Status         string `json:"status"`
	InvestigatorID string `json:"investigator_id,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

type InvestigatorActionRequest struct {
	ActionID       string `json:"action_id"`
	InvestigatorID string `json:"investigator_id"`
	CaseID         string `json:"case_id"`
	Action         string `json:"action"`
	Evidence       string `json:"evidence"`
}

type ModelPredictionRequest struct {
	PredictionID string `json:"prediction_id"`
	ModelVersion string `json:"model_version"`
	Features     string `json:"features"`
	Prediction   string `json:"prediction"`
	ShapValues   string `json:"shap_values"`
}

type TransactionResponse struct {
	TransactionID string          `json:"transaction_id"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}

type HealthResponse struct {
	Status  string            `json:"status"`
	Details map[string]string `json:"details"`
}
