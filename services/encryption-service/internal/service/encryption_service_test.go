package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	commonv1 "github.com/fraud-detection/proto/gen/go/common/v1"
	encryptionv1 "github.com/fraud-detection/proto/gen/go/encryption/v1"
	"github.com/fraud-detection/encryption-service/internal/service"
	"github.com/fraud-detection/encryption-service/internal/vault"
)

// ---------------------------------------------------------------------------
// Mock VaultOperations
// ---------------------------------------------------------------------------

type mockVault struct {
	mock.Mock
}

func (m *mockVault) Encrypt(ctx context.Context, keyName string, plaintext []byte, contextStr string) (string, int32, error) {
	args := m.Called(ctx, keyName, plaintext, contextStr)
	return args.String(0), int32(args.Int(1)), args.Error(2)
}

func (m *mockVault) Decrypt(ctx context.Context, keyName string, ciphertext string, contextStr string) ([]byte, error) {
	args := m.Called(ctx, keyName, ciphertext, contextStr)
	v := args.Get(0)
	if v == nil {
		return nil, args.Error(1)
	}
	return v.([]byte), args.Error(1)
}

func (m *mockVault) Rewrap(ctx context.Context, keyName string, ciphertexts []string, contextStr string) ([]string, int32, error) {
	args := m.Called(ctx, keyName, ciphertexts, contextStr)
	v := args.Get(0)
	if v == nil {
		return nil, int32(args.Int(1)), args.Error(2)
	}
	return v.([]string), int32(args.Int(1)), args.Error(2)
}

func (m *mockVault) GetKeyMetadata(ctx context.Context, keyName string) (*vault.KeyMetadata, error) {
	args := m.Called(ctx, keyName)
	v := args.Get(0)
	if v == nil {
		return nil, args.Error(1)
	}
	return v.(*vault.KeyMetadata), args.Error(1)
}

func (m *mockVault) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSvc(mv *mockVault) *service.EncryptionService {
	return service.New(mv, "fraud-pii-key", 100, zerolog.Nop())
}

// ---------------------------------------------------------------------------
// EncryptPII tests
// ---------------------------------------------------------------------------

func TestEncryptPII_Success(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	plaintext := []byte("sensitive-data")
	expectedCt := "vault:v1:abc123"

	mv.On("Encrypt", mock.Anything, "fraud-pii-key", plaintext, "").
		Return(expectedCt, 1, nil)

	resp, err := svc.EncryptPII(context.Background(), &encryptionv1.EncryptPIIRequest{
		Plaintext: plaintext,
	})

	require.NoError(t, err)
	assert.Equal(t, expectedCt, resp.Ciphertext)
	assert.Equal(t, int32(1), resp.KeyVersion)
	mv.AssertExpectations(t)
}

func TestEncryptPII_EmptyPlaintext_ReturnsInvalidArgument(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	_, err := svc.EncryptPII(context.Background(), &encryptionv1.EncryptPIIRequest{
		Plaintext: []byte{},
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	mv.AssertNotCalled(t, "Encrypt")
}

func TestEncryptPII_VaultError_ReturnsInternal(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Encrypt", mock.Anything, "fraud-pii-key", []byte("data"), "").
		Return("", 0, errors.New("unexpected internal error"))

	_, err := svc.EncryptPII(context.Background(), &encryptionv1.EncryptPIIRequest{
		Plaintext: []byte("data"),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	mv.AssertExpectations(t)
}

func TestEncryptPII_UsesDefaultKeyWhenKeyNameEmpty(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Encrypt", mock.Anything, "fraud-pii-key", []byte("x"), "").
		Return("vault:v1:zzz", 1, nil)

	resp, err := svc.EncryptPII(context.Background(), &encryptionv1.EncryptPIIRequest{
		KeyName:   "", // empty — should fall back to default
		Plaintext: []byte("x"),
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
	mv.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// DecryptPII tests
// ---------------------------------------------------------------------------

func TestDecryptPII_Success(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	ciphertext := "vault:v1:abc123"
	expectedPlain := []byte("secret") // DO NOT LOG

	mv.On("Decrypt", mock.Anything, "fraud-pii-key", ciphertext, "").
		Return(expectedPlain, nil)

	resp, err := svc.DecryptPII(context.Background(), &encryptionv1.DecryptPIIRequest{
		Ciphertext: ciphertext,
	})

	require.NoError(t, err)
	assert.Equal(t, expectedPlain, resp.Plaintext)
	mv.AssertExpectations(t)
}

func TestDecryptPII_InvalidCiphertextFormat_ReturnsInvalidArgument(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	_, err := svc.DecryptPII(context.Background(), &encryptionv1.DecryptPIIRequest{
		Ciphertext: "not-a-vault-ciphertext",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	mv.AssertNotCalled(t, "Decrypt")
}

func TestDecryptPII_VaultError_ReturnsInternal(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Decrypt", mock.Anything, "fraud-pii-key", "vault:v1:bad", "").
		Return(nil, errors.New("some vault error"))

	_, err := svc.DecryptPII(context.Background(), &encryptionv1.DecryptPIIRequest{
		Ciphertext: "vault:v1:bad",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	mv.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// BatchEncrypt tests
// ---------------------------------------------------------------------------

func TestBatchEncrypt_Success(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Encrypt", mock.Anything, "fraud-pii-key", []byte("val1"), "").
		Return("vault:v1:ct1", 1, nil)
	mv.On("Encrypt", mock.Anything, "fraud-pii-key", []byte("val2"), "").
		Return("vault:v1:ct2", 1, nil)

	resp, err := svc.BatchEncrypt(context.Background(), &encryptionv1.BatchEncryptRequest{
		Fields: []*encryptionv1.EncryptField{
			{FieldName: "ssn", Plaintext: []byte("val1")},
			{FieldName: "dob", Plaintext: []byte("val2")},
		},
	})

	require.NoError(t, err)
	require.Len(t, resp.Fields, 2)
	assert.Equal(t, "ssn", resp.Fields[0].FieldName)
	assert.Equal(t, "vault:v1:ct1", resp.Fields[0].Ciphertext)
	assert.Equal(t, "dob", resp.Fields[1].FieldName)
	mv.AssertExpectations(t)
}

func TestBatchEncrypt_TooLarge_ReturnsInvalidArgument(t *testing.T) {
	mv := new(mockVault)
	// Create a service with a very small max batch size.
	svc := service.New(mv, "fraud-pii-key", 2, zerolog.Nop())

	fields := make([]*encryptionv1.EncryptField, 3)
	for i := range fields {
		fields[i] = &encryptionv1.EncryptField{FieldName: "f", Plaintext: []byte("v")}
	}

	_, err := svc.BatchEncrypt(context.Background(), &encryptionv1.BatchEncryptRequest{
		Fields: fields,
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	mv.AssertNotCalled(t, "Encrypt")
}

// ---------------------------------------------------------------------------
// GenerateIdentityHash tests
// ---------------------------------------------------------------------------

func TestGenerateIdentityHash_Determinism(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	req := &encryptionv1.GenerateIdentityHashRequest{
		FullName:       "Jane Doe",
		DateOfBirth:    "1990-01-15",
		DocumentNumber: "P123456",
		DocumentType:   "passport",
		CountryCode:    "US",
	}

	resp1, err := svc.GenerateIdentityHash(context.Background(), req)
	require.NoError(t, err)

	resp2, err := svc.GenerateIdentityHash(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, resp1.IdentityHash, resp2.IdentityHash, "same inputs must produce same hash")
	assert.Equal(t, "SHA-256", resp1.Algorithm)
}

func TestGenerateIdentityHash_Normalization(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	// These two requests differ only in casing/whitespace — they must produce the same hash.
	req1 := &encryptionv1.GenerateIdentityHashRequest{
		FullName:       "jane doe",
		DateOfBirth:    "1990-01-15",
		DocumentNumber: "P123456",
		DocumentType:   "passport",
		CountryCode:    "us",
	}
	req2 := &encryptionv1.GenerateIdentityHashRequest{
		FullName:       "  JANE DOE  ",
		DateOfBirth:    "1990-01-15",
		DocumentNumber: "P123456",
		DocumentType:   "passport",
		CountryCode:    "US",
	}

	resp1, err := svc.GenerateIdentityHash(context.Background(), req1)
	require.NoError(t, err)

	resp2, err := svc.GenerateIdentityHash(context.Background(), req2)
	require.NoError(t, err)

	assert.Equal(t, resp1.IdentityHash, resp2.IdentityHash, "normalised inputs must produce same hash")
}

func TestGenerateIdentityHash_DifferentInputs_DifferentHash(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	base := &encryptionv1.GenerateIdentityHashRequest{
		FullName:       "Jane Doe",
		DateOfBirth:    "1990-01-15",
		DocumentNumber: "P123456",
		DocumentType:   "passport",
		CountryCode:    "US",
	}
	other := &encryptionv1.GenerateIdentityHashRequest{
		FullName:       "John Smith",
		DateOfBirth:    "1985-03-22",
		DocumentNumber: "Q999999",
		DocumentType:   "passport",
		CountryCode:    "GB",
	}

	resp1, err := svc.GenerateIdentityHash(context.Background(), base)
	require.NoError(t, err)

	resp2, err := svc.GenerateIdentityHash(context.Background(), other)
	require.NoError(t, err)

	assert.NotEqual(t, resp1.IdentityHash, resp2.IdentityHash)
}

func TestGenerateIdentityHash_MissingField_ReturnsInvalidArgument(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	_, err := svc.GenerateIdentityHash(context.Background(), &encryptionv1.GenerateIdentityHashRequest{
		FullName: "Jane Doe",
		// DateOfBirth intentionally omitted
		DocumentNumber: "P123456",
		DocumentType:   "passport",
		CountryCode:    "US",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// HealthCheck tests
// ---------------------------------------------------------------------------

func TestHealthCheck_VaultUp_ReturnsServing(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Ping", mock.Anything).Return(nil)

	resp, err := svc.HealthCheck(context.Background(), &commonv1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, commonv1.HealthStatus_HEALTH_STATUS_SERVING, resp.Status)
	mv.AssertExpectations(t)
}

func TestHealthCheck_VaultDown_ReturnsNotServing(t *testing.T) {
	mv := new(mockVault)
	svc := newSvc(mv)

	mv.On("Ping", mock.Anything).Return(errors.New("connection refused"))

	resp, err := svc.HealthCheck(context.Background(), &commonv1.HealthCheckRequest{})
	require.NoError(t, err) // HealthCheck itself does not error; it returns a status
	assert.Equal(t, commonv1.HealthStatus_HEALTH_STATUS_NOT_SERVING, resp.Status)
	assert.Contains(t, resp.Details, "connection refused")
	mv.AssertExpectations(t)
}
