// Package clients provides HTTP clients for downstream services.
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// BlockchainClient calls the Blockchain Service internal HTTP API to anchor
// fraud alerts on Hyperledger Fabric's alert-channel.
type BlockchainClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewBlockchainClient creates a BlockchainClient targeting the given base URL
// (e.g. http://localhost:9005).
func NewBlockchainClient(baseURL string) *BlockchainClient {
	return &BlockchainClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// createAlertPayload matches the Blockchain Service domain.CreateAlertRequest.
type createAlertPayload struct {
	AlertID      string  `json:"alert_id"`
	CustomerID   string  `json:"customer_id"`
	TxHash       string  `json:"tx_hash"`
	FraudProb    float64 `json:"fraud_probability"`
	RiskScore    float64 `json:"risk_score"`
	ModelVersion string  `json:"model_version"`
}

// transactionResponse matches the Blockchain Service domain.TransactionResponse.
type transactionResponse struct {
	TransactionID string `json:"transaction_id"`
}

// CreateAlert anchors a fraud alert on the Fabric alert-channel via the
// Blockchain Service. Returns the Fabric transaction ID on success.
// This is a non-fatal call — failures are logged but do not block alert ingest.
func (c *BlockchainClient) CreateAlert(
	ctx context.Context,
	alertID, customerID, txHash, modelVersion string,
	fraudProb, riskScore float64,
) (string, error) {
	payload := createAlertPayload{
		AlertID:      alertID,
		CustomerID:   customerID,
		TxHash:       txHash,
		FraudProb:    fraudProb,
		RiskScore:    riskScore,
		ModelVersion: modelVersion,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal alert payload: %w", err)
	}

	url := c.baseURL + "/internal/v1/alerts/create"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build alert anchor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("alert_id", alertID).
			Msg("blockchain service unreachable — alert not anchored on alert-channel")
		return "", fmt.Errorf("blockchain http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("blockchain service returned HTTP %d for alert anchor", resp.StatusCode)
	}

	var result transactionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode alert anchor response: %w", err)
	}

	log.Info().
		Str("blockchain_tx_id", result.TransactionID).
		Str("alert_id", alertID).
		Str("customer_id", customerID).
		Msg("alert anchored on Fabric alert-channel")

	return result.TransactionID, nil
}

// Ping checks connectivity to the Blockchain Service.
func (c *BlockchainClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("blockchain health returned %d", resp.StatusCode)
	}
	return nil
}
