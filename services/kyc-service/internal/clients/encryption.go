// Package clients provides gRPC client wrappers for downstream services.
package clients

import (
	"context"
	"fmt"

	encryptionv1 "github.com/fraud-detection/proto/gen/go/encryption/v1"
	"github.com/fraud-detection/shared/grpcclient"
	"github.com/rs/zerolog"
)

// EncryptionClient wraps the Encryption Service gRPC client.
// It provides high-level helpers for PII batch encryption, decryption,
// and identity hash generation. NEVER log decrypted values.
type EncryptionClient struct {
	client encryptionv1.EncryptionServiceClient
	log    zerolog.Logger
}

// NewEncryptionClient dials the Encryption Service and returns a ready client.
// addr should be "host:port", e.g. "encryption-service:50064".
func NewEncryptionClient(addr string, log zerolog.Logger) (*EncryptionClient, error) {
	conn, err := grpcclient.New(context.Background(), grpcclient.Config{
		Target:        addr,
		CallerService: "kyc-service",
		TLS:           false, // enable in production
		Log:           log,
	})
	if err != nil {
		return nil, fmt.Errorf("dial encryption service at %s: %w", addr, err)
	}

	return &EncryptionClient{
		client: encryptionv1.NewEncryptionServiceClient(conn),
		log:    log.With().Str("component", "encryption_client").Logger(),
	}, nil
}

// BatchEncryptPII encrypts a map of PII field names to plaintext bytes.
// Returns a map of field names to Vault Transit ciphertexts.
// The customerID is used as the encryption context for key derivation.
// NEVER log the input map — it contains raw PII.
func (c *EncryptionClient) BatchEncryptPII(ctx context.Context, customerID string, fields map[string][]byte) (map[string]string, error) {
	if len(fields) == 0 {
		return map[string]string{}, nil
	}

	encFields := make([]*encryptionv1.EncryptField, 0, len(fields))
	for name, plaintext := range fields {
		encFields = append(encFields, &encryptionv1.EncryptField{
			FieldName: name,
			Plaintext: plaintext,
			Context:   customerID,
		})
	}

	req := &encryptionv1.BatchEncryptRequest{
		KeyName: "kyc-pii",
		Fields:  encFields,
	}

	resp, err := c.client.BatchEncrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("batch encrypt PII: %w", err)
	}

	result := make(map[string]string, len(resp.Fields))
	for _, f := range resp.Fields {
		result[f.FieldName] = f.Ciphertext
	}

	c.log.Debug().
		Str("customer_id", customerID).
		Int("field_count", len(result)).
		Msg("PII fields encrypted") // field names only — no values

	return result, nil
}

// BatchDecryptPII decrypts a map of field names to Vault Transit ciphertexts.
// Returns a map of field names to plaintext bytes.
// NEVER log the returned map — it contains raw PII.
func (c *EncryptionClient) BatchDecryptPII(ctx context.Context, customerID string, ciphertexts map[string]string) (map[string][]byte, error) {
	if len(ciphertexts) == 0 {
		return map[string][]byte{}, nil
	}

	decFields := make([]*encryptionv1.DecryptField, 0, len(ciphertexts))
	for name, cipher := range ciphertexts {
		decFields = append(decFields, &encryptionv1.DecryptField{
			FieldName:  name,
			Ciphertext: cipher,
			Context:    customerID,
		})
	}

	req := &encryptionv1.BatchDecryptRequest{
		KeyName: "kyc-pii",
		Fields:  decFields,
	}

	resp, err := c.client.BatchDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("batch decrypt PII: %w", err)
	}

	result := make(map[string][]byte, len(resp.Fields))
	for _, f := range resp.Fields {
		result[f.FieldName] = f.Plaintext
	}

	c.log.Debug().
		Str("customer_id", customerID).
		Int("field_count", len(result)).
		Msg("PII fields decrypted") // DO NOT LOG field values

	return result, nil
}

// GenerateIdentityHash requests a deterministic, privacy-preserving identity hash
// from the Encryption Service. The hash is safe to store plaintext in the database
// because it is a one-way HMAC — it cannot be reversed to recover PII.
func (c *EncryptionClient) GenerateIdentityHash(
	ctx context.Context,
	fullName, dob, docType, docNumber, countryCode string,
) (string, error) {
	req := &encryptionv1.GenerateIdentityHashRequest{
		// NOTE: these fields are sent to the encryption service over an
		// authenticated internal gRPC channel. They are NOT logged here.
		FullName:       fullName,
		DateOfBirth:    dob,
		DocumentNumber: docNumber,
		DocumentType:   docType,
		CountryCode:    countryCode,
	}

	resp, err := c.client.GenerateIdentityHash(ctx, req)
	if err != nil {
		return "", fmt.Errorf("generate identity hash: %w", err)
	}

	c.log.Debug().
		Str("algorithm", resp.Algorithm).
		Msg("identity hash generated") // hash value is safe to omit from logs

	return resp.IdentityHash, nil
}
