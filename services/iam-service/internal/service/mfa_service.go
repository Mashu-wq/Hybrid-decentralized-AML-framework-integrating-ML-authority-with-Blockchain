// Package service contains the IAM business logic layer.
package service

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// MFAService handles TOTP-based multi-factor authentication and backup codes.
type MFAService struct {
	issuer string
}

// NewMFAService creates a new MFAService with the given TOTP issuer name
// (displayed in authenticator apps, e.g. "FraudDetectionSystem").
func NewMFAService(issuer string) *MFAService {
	return &MFAService{issuer: issuer}
}

// GenerateSecret creates a new TOTP secret and OTP auth URL for a user.
// The secret is base32-encoded and should be stored encrypted at rest.
// The otpAuthURL is safe to encode as a QR code for the user's authenticator app.
func (s *MFAService) GenerateSecret(email string) (secret, otpAuthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Verify checks whether a TOTP code is valid for the given base32 secret.
// Uses the default 30-second window with ±1 step tolerance (built into pquerna/otp).
func (s *MFAService) Verify(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates n random one-time backup codes.
// Returns (rawCodes, hashedCodes, error).
// rawCodes are shown to the user exactly once and must not be stored.
// hashedCodes (bcrypt, cost 12) are stored in the database.
func (s *MFAService) GenerateBackupCodes(n int) (rawCodes []string, hashedCodes []string, err error) {
	rawCodes = make([]string, n)
	hashedCodes = make([]string, n)

	for i := 0; i < n; i++ {
		// 10 random bytes → 20 hex chars; formatted as XXXXX-XXXXX for readability
		b := make([]byte, 10)
		if _, readErr := rand.Read(b); readErr != nil {
			return nil, nil, fmt.Errorf("generate backup code entropy: %w", readErr)
		}
		raw := fmt.Sprintf("%x", b)
		rawCodes[i] = raw[:5] + "-" + raw[5:]

		hash, hashErr := bcrypt.GenerateFromPassword([]byte(rawCodes[i]), 12)
		if hashErr != nil {
			return nil, nil, fmt.Errorf("hash backup code: %w", hashErr)
		}
		hashedCodes[i] = string(hash)
	}
	return rawCodes, hashedCodes, nil
}

// VerifyBackupCode checks a raw code against a slice of bcrypt-hashed codes.
// Returns (valid, matchIndex, error).
// All hashes are checked to prevent timing attacks leaking the index of a valid code.
func (s *MFAService) VerifyBackupCode(code string, hashedCodes []string) (bool, int, error) {
	matched := false
	matchIndex := -1
	codeBytes := []byte(code)

	for i, hashed := range hashedCodes {
		err := bcrypt.CompareHashAndPassword([]byte(hashed), codeBytes)
		if err == nil {
			// Use subtle.ConstantTimeSelect to prevent the compiler from
			// short-circuiting the remaining iterations.
			_ = subtle.ConstantTimeSelect(1, 1, 0)
			if !matched {
				matched = true
				matchIndex = i
			}
		}
	}
	return matched, matchIndex, nil
}
