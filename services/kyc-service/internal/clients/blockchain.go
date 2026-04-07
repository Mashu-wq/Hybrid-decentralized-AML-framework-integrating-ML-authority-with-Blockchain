// Package clients — stub blockchain client.
// Phase 6 will replace this with a real gRPC client to the blockchain service.
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fraud-detection/kyc-service/internal/domain"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// BlockchainClient is the interface for anchoring KYC events on-chain.
// The real implementation (Phase 6) will call the blockchain-service gRPC API.
type BlockchainClient interface {
	// RegisterKYCOnChain anchors a new customer KYC registration on the ledger.
	// Returns the blockchain transaction ID on success.
	RegisterKYCOnChain(
		ctx context.Context,
		customerID, identityHash string,
		status domain.KYCStatus,
		riskLevel domain.RiskLevel,
		verifierID string,
	) (txID string, err error)

	// UpdateKYCOnChain records a KYC status change on the ledger.
	// Returns the blockchain transaction ID on success.
	UpdateKYCOnChain(
		ctx context.Context,
		customerID string,
		status domain.KYCStatus,
		reason, verifierID string,
	) (txID string, err error)
}

// stubBlockchainClient is a no-op implementation used until Phase 6.
// It logs what would be sent to the blockchain and returns a deterministic stub TX ID.
type stubBlockchainClient struct {
	log zerolog.Logger
}

// remoteBlockchainClient posts KYC ledger requests to the blockchain service.
type remoteBlockchainClient struct {
	baseURL string
	client  *http.Client
	log     zerolog.Logger
}

// NewStubBlockchainClient returns a BlockchainClient that logs operations
// without making any real network calls. Replace with a real client in Phase 6.
func NewStubBlockchainClient(log zerolog.Logger) BlockchainClient {
	return &stubBlockchainClient{
		log: log.With().Str("component", "blockchain_client_stub").Logger(),
	}
}

// NewRemoteBlockchainClient returns an HTTP-backed blockchain service client.
func NewRemoteBlockchainClient(addr string, log zerolog.Logger) BlockchainClient {
	baseURL := strings.TrimRight(addr, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	return &remoteBlockchainClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		log: log.With().Str("component", "blockchain_client").Logger(),
	}
}

// RegisterKYCOnChain logs the registration event and returns a stub TX ID.
func (s *stubBlockchainClient) RegisterKYCOnChain(
	ctx context.Context,
	customerID, identityHash string,
	status domain.KYCStatus,
	riskLevel domain.RiskLevel,
	verifierID string,
) (string, error) {
	txID := fmt.Sprintf("stub-tx-%s", uuid.New().String())

	s.log.Info().
		Str("customer_id", customerID).
		Str("identity_hash", identityHash).
		Str("kyc_status", string(status)).
		Str("risk_level", string(riskLevel)).
		Str("verifier_id", verifierID).
		Str("stub_tx_id", txID).
		Msg("[STUB] would anchor KYC registration on blockchain — Phase 6 pending")

	return txID, nil
}

// UpdateKYCOnChain logs the status update event and returns a stub TX ID.
func (s *stubBlockchainClient) UpdateKYCOnChain(
	ctx context.Context,
	customerID string,
	status domain.KYCStatus,
	reason, verifierID string,
) (string, error) {
	txID := fmt.Sprintf("stub-tx-%s", uuid.New().String())

	s.log.Info().
		Str("customer_id", customerID).
		Str("kyc_status", string(status)).
		Str("verifier_id", verifierID).
		Str("stub_tx_id", txID).
		Msg("[STUB] would anchor KYC status update on blockchain — Phase 6 pending")

	return txID, nil
}

type registerKYCRequest struct {
	CustomerID   string `json:"customer_id"`
	IdentityHash string `json:"identity_hash"`
	KYCStatus    string `json:"kyc_status"`
	RiskLevel    string `json:"risk_level"`
	VerifierID   string `json:"verifier_id,omitempty"`
}

type updateKYCRequest struct {
	CustomerID string `json:"customer_id"`
	KYCStatus  string `json:"kyc_status"`
	Reason     string `json:"reason,omitempty"`
	VerifierID string `json:"verifier_id,omitempty"`
}

type blockchainResponse struct {
	TransactionID string `json:"transaction_id"`
}

// RegisterKYCOnChain triggers blockchain-service registration for a customer.
func (c *remoteBlockchainClient) RegisterKYCOnChain(
	ctx context.Context,
	customerID, identityHash string,
	status domain.KYCStatus,
	riskLevel domain.RiskLevel,
	verifierID string,
) (string, error) {
	payload := registerKYCRequest{
		CustomerID:   customerID,
		IdentityHash: identityHash,
		KYCStatus:    string(status),
		RiskLevel:    string(riskLevel),
		VerifierID:   verifierID,
	}

	var resp blockchainResponse
	if err := c.post(ctx, "/internal/v1/kyc/register", payload, &resp); err != nil {
		return "", err
	}
	return resp.TransactionID, nil
}

// UpdateKYCOnChain triggers blockchain-service status anchoring for a customer.
func (c *remoteBlockchainClient) UpdateKYCOnChain(
	ctx context.Context,
	customerID string,
	status domain.KYCStatus,
	reason, verifierID string,
) (string, error) {
	payload := updateKYCRequest{
		CustomerID: customerID,
		KYCStatus:  string(status),
		Reason:     reason,
		VerifierID: verifierID,
	}

	var resp blockchainResponse
	if err := c.post(ctx, "/internal/v1/kyc/status", payload, &resp); err != nil {
		return "", err
	}
	return resp.TransactionID, nil
}

func (c *remoteBlockchainClient) post(ctx context.Context, path string, payload interface{}, out *blockchainResponse) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal blockchain request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create blockchain request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("call blockchain service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("blockchain service returned status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode blockchain response: %w", err)
	}

	c.log.Info().
		Str("path", path).
		Str("transaction_id", out.TransactionID).
		Msg("blockchain service request completed")

	return nil
}
