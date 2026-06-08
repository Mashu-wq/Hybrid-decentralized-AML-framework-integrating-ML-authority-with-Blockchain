// Package clients — BlockchainAnchorClient sends a TRANSACTION_PROCESSED receipt
// to the blockchain-service audit-channel endpoint after every ML-scored transaction.
// All calls are fire-and-forget: the hot pipeline is never blocked on Fabric commit.
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fraud-detection/transaction-service/internal/domain"
	"github.com/rs/zerolog"
)

// BlockchainAnchorClient implements service.BlockchainAnchor by calling the
// blockchain-service HTTP API. Failures are logged and silently dropped.
type BlockchainAnchorClient struct {
	baseURL    string
	httpClient *http.Client
	log        zerolog.Logger
}

func NewBlockchainAnchorClient(baseURL string, log zerolog.Logger) *BlockchainAnchorClient {
	return &BlockchainAnchorClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		log:        log.With().Str("component", "blockchain_anchor").Logger(),
	}
}

// transactionReceiptPayload mirrors blockchain-service/domain.TransactionReceiptRequest.
type transactionReceiptPayload struct {
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

// AnchorTransactionReceipt fires an async goroutine that POSTs the receipt to the
// blockchain-service. It never blocks the caller and never returns an error.
func (c *BlockchainAnchorClient) AnchorTransactionReceipt(enriched *domain.EnrichedTransaction) {
	go c.post(enriched)
}

func (c *BlockchainAnchorClient) post(enriched *domain.EnrichedTransaction) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p := c.buildPayload(enriched)

	body, err := json.Marshal(p)
	if err != nil {
		c.log.Error().Err(err).Str("tx_hash", enriched.TxHash).
			Msg("blockchain anchor: marshal payload failed")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/internal/v1/audit/transaction-receipt",
		bytes.NewReader(body),
	)
	if err != nil {
		c.log.Error().Err(err).Str("tx_hash", enriched.TxHash).
			Msg("blockchain anchor: build request failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Warn().Err(err).Str("tx_hash", enriched.TxHash).
			Msg("blockchain anchor: HTTP call failed (non-fatal — Fabric may be unavailable)")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.log.Warn().
			Str("tx_hash", enriched.TxHash).
			Int("status_code", resp.StatusCode).
			Msg(fmt.Sprintf("blockchain anchor: non-200 response (non-fatal)"))
		return
	}

	c.log.Info().
		Str("tx_hash", enriched.TxHash).
		Str("customer_id", enriched.CustomerID).
		Float64("fraud_prob", enriched.FraudProbability).
		Str("risk_level", enriched.RiskLevel.String()).
		Bool("alert_fired", enriched.AlertCreated).
		Msg("transaction receipt anchored to blockchain audit-channel")
}

func (c *BlockchainAnchorClient) buildPayload(enriched *domain.EnrichedTransaction) transactionReceiptPayload {
	amountUSD := 0.0
	currencyCode := ""
	channel := ""
	countryCode := ""

	if enriched.Raw != nil {
		currencyCode = enriched.Raw.CurrencyCode
		channel = enriched.Raw.Channel
		countryCode = enriched.Raw.CountryCode
	}
	if enriched.Features != nil {
		amountUSD = enriched.Features.AmountUSDEquiv
	}

	return transactionReceiptPayload{
		RecordID:         enriched.TxHash,
		TxHash:           enriched.TxHash,
		CustomerID:       enriched.CustomerID,
		AmountUSD:        amountUSD,
		CurrencyCode:     currencyCode,
		Channel:          channel,
		CountryCode:      countryCode,
		ProcessedAt:      enriched.ProcessedAt.UTC().Format(time.RFC3339),
		FraudProbability: enriched.FraudProbability,
		RiskLevel:        enriched.RiskLevel.String(),
		AlertFired:       enriched.AlertCreated,
		AlertID:          enriched.AlertID,
		ModelVersion:     enriched.ModelVersion,
		PredictionID:     enriched.PredictionID,
	}
}
