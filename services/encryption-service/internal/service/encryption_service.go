// Package service implements the gRPC EncryptionService business logic.
// This layer orchestrates all Vault Transit calls. Raw plaintext PII never
// leaves this package — it is received from callers and forwarded directly to
// the vault package, which is the only place that holds decrypted bytes.
package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	encryptionv1 "github.com/fraud-detection/proto/gen/go/encryption/v1"
	"github.com/fraud-detection/encryption-service/internal/vault"
)

// VaultOperations is the interface the service layer uses to interact with Vault.
// Backed by *vault.VaultClient in production; replaced by mocks in tests.
type VaultOperations interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte, contextStr string) (string, int32, error)
	Decrypt(ctx context.Context, keyName string, ciphertext string, contextStr string) ([]byte, error)
	Rewrap(ctx context.Context, keyName string, ciphertexts []string, contextStr string) ([]string, int32, error)
	GetKeyMetadata(ctx context.Context, keyName string) (*vault.KeyMetadata, error)
	Ping(ctx context.Context) error
}

// EncryptionService implements encryptionv1.EncryptionServiceServer.
type EncryptionService struct {
	encryptionv1.UnimplementedEncryptionServiceServer

	vault      VaultOperations
	defaultKey string
	maxBatch   int
	log        zerolog.Logger
}

// New creates a new EncryptionService.
func New(v VaultOperations, defaultKey string, maxBatch int, log zerolog.Logger) *EncryptionService {
	return &EncryptionService{
		vault:      v,
		defaultKey: defaultKey,
		maxBatch:   maxBatch,
		log:        log,
	}
}

// EncryptPII encrypts a single plaintext value.
// The request plaintext MUST NOT be logged.
func (s *EncryptionService) EncryptPII(ctx context.Context, req *encryptionv1.EncryptPIIRequest) (*encryptionv1.EncryptPIIResponse, error) {
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext must not be empty")
	}

	keyName := s.resolveKey(req.KeyName)

	// IMPORTANT: do not log req.Plaintext — it contains PII.
	ct, kv, err := s.vault.Encrypt(ctx, keyName, req.Plaintext, req.Context)
	if err != nil {
		s.log.Error().Err(err).Str("key_name", keyName).Msg("vault encrypt failed")
		return nil, s.vaultErr(err)
	}

	return &encryptionv1.EncryptPIIResponse{
		Ciphertext: ct,
		KeyVersion: kv,
	}, nil
}

// DecryptPII decrypts a Vault Transit ciphertext.
// The returned plaintext MUST NOT be logged by any caller.
func (s *EncryptionService) DecryptPII(ctx context.Context, req *encryptionv1.DecryptPIIRequest) (*encryptionv1.DecryptPIIResponse, error) {
	if !strings.HasPrefix(req.Ciphertext, "vault:") {
		return nil, status.Error(codes.InvalidArgument, "ciphertext must start with 'vault:'")
	}

	keyName := s.resolveKey(req.KeyName)

	// IMPORTANT: do not log the decrypted result — it contains PII.
	plaintext, err := s.vault.Decrypt(ctx, keyName, req.Ciphertext, req.Context)
	if err != nil {
		s.log.Error().Err(err).Str("key_name", keyName).Msg("vault decrypt failed")
		return nil, s.vaultErr(err)
	}

	return &encryptionv1.DecryptPIIResponse{
		Plaintext: plaintext, // DO NOT LOG
	}, nil
}

// BatchEncrypt encrypts multiple named fields in a single RPC.
func (s *EncryptionService) BatchEncrypt(ctx context.Context, req *encryptionv1.BatchEncryptRequest) (*encryptionv1.BatchEncryptResponse, error) {
	if len(req.Fields) == 0 {
		return nil, status.Error(codes.InvalidArgument, "fields must not be empty")
	}
	if len(req.Fields) > s.maxBatch {
		return nil, status.Errorf(codes.InvalidArgument, "batch size %d exceeds maximum %d", len(req.Fields), s.maxBatch)
	}

	keyName := s.resolveKey(req.KeyName)
	results := make([]*encryptionv1.EncryptedField, 0, len(req.Fields))

	for _, f := range req.Fields {
		if f == nil {
			return nil, status.Error(codes.InvalidArgument, "nil field in batch")
		}
		if len(f.Plaintext) == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "field %q: plaintext must not be empty", f.FieldName)
		}

		// IMPORTANT: do not log f.Plaintext — it contains PII.
		ct, kv, err := s.vault.Encrypt(ctx, keyName, f.Plaintext, f.Context)
		if err != nil {
			s.log.Error().Err(err).Str("key_name", keyName).Str("field_name", f.FieldName).Msg("vault batch encrypt failed")
			return nil, s.vaultErr(err)
		}

		results = append(results, &encryptionv1.EncryptedField{
			FieldName:  f.FieldName,
			Ciphertext: ct,
			KeyVersion: kv,
		})
	}

	return &encryptionv1.BatchEncryptResponse{Fields: results}, nil
}

// BatchDecrypt decrypts multiple named fields in a single RPC.
// The returned plaintexts MUST NOT be logged by callers.
func (s *EncryptionService) BatchDecrypt(ctx context.Context, req *encryptionv1.BatchDecryptRequest) (*encryptionv1.BatchDecryptResponse, error) {
	if len(req.Fields) == 0 {
		return nil, status.Error(codes.InvalidArgument, "fields must not be empty")
	}
	if len(req.Fields) > s.maxBatch {
		return nil, status.Errorf(codes.InvalidArgument, "batch size %d exceeds maximum %d", len(req.Fields), s.maxBatch)
	}

	keyName := s.resolveKey(req.KeyName)
	results := make([]*encryptionv1.DecryptedField, 0, len(req.Fields))

	for _, f := range req.Fields {
		if f == nil {
			return nil, status.Error(codes.InvalidArgument, "nil field in batch")
		}
		if !strings.HasPrefix(f.Ciphertext, "vault:") {
			return nil, status.Errorf(codes.InvalidArgument, "field %q: ciphertext must start with 'vault:'", f.FieldName)
		}

		// IMPORTANT: do not log the decrypted result — it contains PII.
		plaintext, err := s.vault.Decrypt(ctx, keyName, f.Ciphertext, f.Context)
		if err != nil {
			s.log.Error().Err(err).Str("key_name", keyName).Str("field_name", f.FieldName).Msg("vault batch decrypt failed")
			return nil, s.vaultErr(err)
		}

		results = append(results, &encryptionv1.DecryptedField{
			FieldName: f.FieldName,
			Plaintext: plaintext, // DO NOT LOG
		})
	}

	return &encryptionv1.BatchDecryptResponse{Fields: results}, nil
}

// RewrapKey re-encrypts ciphertexts under the latest key version.
func (s *EncryptionService) RewrapKey(ctx context.Context, req *encryptionv1.RewrapKeyRequest) (*encryptionv1.RewrapKeyResponse, error) {
	if len(req.Ciphertexts) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertexts must not be empty")
	}

	keyName := s.resolveKey(req.KeyName)

	newCts, newKV, err := s.vault.Rewrap(ctx, keyName, req.Ciphertexts, req.Context)
	if err != nil {
		s.log.Error().Err(err).Str("key_name", keyName).Msg("vault rewrap failed")
		return nil, s.vaultErr(err)
	}

	return &encryptionv1.RewrapKeyResponse{
		NewCiphertexts: newCts,
		NewKeyVersion:  newKV,
	}, nil
}

// GenerateIdentityHash creates a stable, privacy-preserving SHA-256 hash of PII
// fields for deduplication. The inputs are normalised before hashing so that
// minor formatting differences produce the same hash.
//
// IMPORTANT: Do not log the input fields — they contain raw PII.
func (s *EncryptionService) GenerateIdentityHash(ctx context.Context, req *encryptionv1.GenerateIdentityHashRequest) (*encryptionv1.GenerateIdentityHashResponse, error) {
	if req.FullName == "" || req.DateOfBirth == "" || req.DocumentNumber == "" || req.DocumentType == "" || req.CountryCode == "" {
		return nil, status.Error(codes.InvalidArgument, "all identity fields are required")
	}

	// Normalise inputs to ensure determinism regardless of caller formatting.
	fullName := strings.ToLower(strings.TrimSpace(req.FullName))
	dateOfBirth := strings.TrimSpace(req.DateOfBirth)
	documentType := strings.TrimSpace(req.DocumentType)
	documentNumber := strings.TrimSpace(req.DocumentNumber)
	countryCode := strings.ToUpper(strings.TrimSpace(req.CountryCode))

	// Concatenate in fixed order with '|' separator.
	// IMPORTANT: do not log this string — it encodes PII.
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s",
		fullName, dateOfBirth, documentType, documentNumber, countryCode)

	sum := sha256.Sum256([]byte(canonical))
	hash := fmt.Sprintf("%x", sum)

	return &encryptionv1.GenerateIdentityHashResponse{
		IdentityHash: hash,
		Algorithm:    "SHA-256",
	}, nil
}

// GetKeyInfo retrieves Transit key metadata.
func (s *EncryptionService) GetKeyInfo(ctx context.Context, req *encryptionv1.GetKeyInfoRequest) (*encryptionv1.GetKeyInfoResponse, error) {
	keyName := s.resolveKey(req.KeyName)

	meta, err := s.vault.GetKeyMetadata(ctx, keyName)
	if err != nil {
		s.log.Error().Err(err).Str("key_name", keyName).Msg("get key metadata failed")
		return nil, s.vaultErr(err)
	}

	return &encryptionv1.GetKeyInfoResponse{
		KeyName:           meta.Name,
		CurrentVersion:    meta.CurrentVersion,
		MinDecryptVersion: meta.MinDecryptVersion,
		RotationPeriod:    meta.RotationPeriod,
		DeletionAllowed:   meta.DeletionAllowed,
	}, nil
}

// HealthCheck reports whether the service is able to reach Vault.
func (s *EncryptionService) HealthCheck(ctx context.Context, req *commonv1.HealthCheckRequest) (*commonv1.HealthCheckResponse, error) {
	if err := s.vault.Ping(ctx); err != nil {
		s.log.Warn().Err(err).Msg("vault ping failed during health check")
		return &commonv1.HealthCheckResponse{
			Status:  commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING,
			Details: err.Error(),
		}, nil
	}

	return &commonv1.HealthCheckResponse{
		Status:  commonv1.HealthStatus_HEALTH_STATUS_SERVING,
		Details: "vault reachable",
	}, nil
}

// resolveKey returns keyName if non-empty, otherwise falls back to the default key.
func (s *EncryptionService) resolveKey(keyName string) string {
	if keyName != "" {
		return keyName
	}
	return s.defaultKey
}

// vaultErr maps vault/network errors to appropriate gRPC status codes.
func (s *EncryptionService) vaultErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "vault is sealed"):
		return status.Errorf(codes.Unavailable, "vault unavailable: %v", err)
	case strings.Contains(msg, "invalid ciphertext"),
		strings.Contains(msg, "invalid key"),
		strings.Contains(msg, "bad input"):
		return status.Errorf(codes.InvalidArgument, "vault error: %v", err)
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "403"):
		return status.Errorf(codes.PermissionDenied, "vault permission denied: %v", err)
	default:
		return status.Errorf(codes.Internal, "internal vault error: %v", err)
	}
}
