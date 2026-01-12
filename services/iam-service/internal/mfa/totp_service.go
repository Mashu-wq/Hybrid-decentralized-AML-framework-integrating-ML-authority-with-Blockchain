// iam-service/internal/mfa/totp_service.go
package mfa

import (
	"crypto/rand"
	"encoding/base32"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type MFAService struct {
	issuer string
}

func NewMFAService(issuer string) *MFAService {
	return &MFAService{issuer: issuer}
}

func (s *MFAService) GenerateTOTP(email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: email,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	
	return key, err
}

func (s *MFAService) ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

func (s *MFAService) GenerateBackupCodes(count int) ([]string, []string, error) {
	var codes []string
	var hashedCodes []string
	
	for i := 0; i < count; i++ {
		code := generateRandomCode(10)
		codes = append(codes, code)
		
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		hashedCodes = append(hashedCodes, string(hashed))
	}
	
	return codes, hashedCodes, nil
}

func generateRandomCode(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base32.StdEncoding.EncodeToString(bytes)[:length]
}