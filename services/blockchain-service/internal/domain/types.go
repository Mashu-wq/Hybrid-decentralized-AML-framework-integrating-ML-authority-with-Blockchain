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
	RiskLevel  string `json:"risk_level,omitempty"`
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

// TransactionReceiptRequest carries the data written to the audit-channel as a
// TRANSACTION_PROCESSED record for every ML-scored transaction.
type TransactionReceiptRequest struct {
	RecordID         string  `json:"record_id"`
	TxHash           string  `json:"tx_hash"`
	CustomerID       string  `json:"customer_id"`
	AmountUSD        float64 `json:"amount_usd"`
	CurrencyCode     string  `json:"currency_code"`
	Channel          string  `json:"channel"`
	CountryCode      string  `json:"country_code"`
	ProcessedAt      string  `json:"processed_at"`
	FraudProbability float64 `json:"fraud_probability"`
	RiskLevel        string  `json:"risk_level"`
	AlertFired       bool    `json:"alert_fired"`
	AlertID          string  `json:"alert_id,omitempty"`
	ModelVersion     string  `json:"model_version"`
	PredictionID     string  `json:"prediction_id,omitempty"`
}

// SARFiledRequest carries the data written to the audit-channel when a SAR PDF is
// generated. The sarHash (SHA-256 of the PDF bytes) proves the document has not been
// altered after filing — a regulator can recompute the hash from the S3 object.
type SARFiledRequest struct {
	RecordID    string `json:"record_id"`
	CaseID      string `json:"case_id"`
	SARHash     string `json:"sar_hash"`
	S3Key       string `json:"s3_key"`
	FiledAt     string `json:"filed_at"`
	GeneratedBy string `json:"generated_by"`
}

type HealthResponse struct {
	Status  string            `json:"status"`
	Details map[string]string `json:"details"`
}
