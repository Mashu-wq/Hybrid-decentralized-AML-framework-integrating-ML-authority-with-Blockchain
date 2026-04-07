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

// BlockchainClient calls the Blockchain Service internal HTTP API to record
// investigator actions on Hyperledger Fabric's audit-channel.
type BlockchainClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewBlockchainClient creates a BlockchainClient targeting the given base URL.
func NewBlockchainClient(baseURL string) *BlockchainClient {
	return &BlockchainClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// investigatorActionPayload matches the Blockchain Service domain.InvestigatorActionRequest.
type investigatorActionPayload struct {
	ActionID       string `json:"action_id"`
	InvestigatorID string `json:"investigator_id"`
	CaseID         string `json:"case_id"`
	Action         string `json:"action"`
	Evidence       string `json:"evidence"`
}

// transactionResponse matches the Blockchain Service domain.TransactionResponse.
type transactionResponse struct {
	TransactionID string `json:"transaction_id"`
}

// RecordInvestigatorAction submits an investigator action to Hyperledger Fabric
// via the Blockchain Service's audit channel.
// Returns the Fabric transaction ID on success.
// This is a non-fatal call — failures are logged but do not block case operations.
func (c *BlockchainClient) RecordInvestigatorAction(
	ctx context.Context,
	actionID, investigatorID, caseID, action, notes string,
) (string, error) {
	payload := investigatorActionPayload{
		ActionID:       actionID,
		InvestigatorID: investigatorID,
		CaseID:         caseID,
		Action:         action,
		Evidence:       notes,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal blockchain payload: %w", err)
	}

	url := c.baseURL + "/internal/v1/audit/investigator-action"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build blockchain request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("action", action).Str("case_id", caseID).
			Msg("blockchain service unreachable — audit will be incomplete")
		return "", fmt.Errorf("blockchain http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("blockchain service returned HTTP %d", resp.StatusCode)
	}

	var result transactionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode blockchain response: %w", err)
	}

	log.Info().
		Str("blockchain_tx_id", result.TransactionID).
		Str("case_id", caseID).
		Str("action", action).
		Msg("action recorded on Fabric audit-channel")

	return result.TransactionID, nil
}

// alertStatusPayload matches the Blockchain Service domain.UpdateAlertStatusRequest.
type alertStatusPayload struct {
	AlertID        string `json:"alert_id"`
	Status         string `json:"status"`
	InvestigatorID string `json:"investigator_id,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

// UpdateAlertStatus records an alert status change on the Fabric alert-channel.
func (c *BlockchainClient) UpdateAlertStatus(
	ctx context.Context,
	alertID, status, investigatorID, notes string,
) (string, error) {
	payload := alertStatusPayload{
		AlertID:        alertID,
		Status:         status,
		InvestigatorID: investigatorID,
		Notes:          notes,
	}
	body, _ := json.Marshal(payload)

	url := c.baseURL + "/internal/v1/alerts/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("blockchain: alert status update failed")
		return "", err
	}
	defer resp.Body.Close()

	var result transactionResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
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
