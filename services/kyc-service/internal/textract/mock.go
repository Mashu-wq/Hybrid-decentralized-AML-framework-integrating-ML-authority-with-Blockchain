// Package textract — mock OCR client for local development and testing.
package textract

import (
	"context"
	"strings"
	"time"

	"github.com/fraud-detection/kyc-service/internal/domain"
)

// MockOCRClient returns realistic mock OCR data without calling AWS Textract.
// Use this in local development (UseMockTextract=true) and unit tests.
type MockOCRClient struct{}

// ExtractDocument returns a synthetic OCRResult with high confidence scores.
// The extracted fields are realistic but obviously fake (suitable for dev/test).
func (m *MockOCRClient) ExtractDocument(ctx context.Context, s3Key, s3Bucket, documentType string) (*domain.OCRResult, error) {
	// Simulate realistic processing delay.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}

	docType := strings.ToUpper(documentType)

	result := &domain.OCRResult{
		Success:    true,
		Confidence: 0.95,
		ExpiryValid: true,
		NameMatch:  true,
	}

	switch {
	case strings.Contains(docType, "PASSPORT"):
		result.ExtractedName   = "JOHN MOCK SMITH"
		result.ExtractedDOB    = "1990-01-15"
		result.ExtractedDocNo  = "P12345678"
		result.ExtractedExpiry = "2030-01-15"

	case strings.Contains(docType, "NATIONAL_ID") || strings.Contains(docType, "NATIONAL ID"):
		result.ExtractedName   = "JOHN MOCK SMITH"
		result.ExtractedDOB    = "1990-01-15"
		result.ExtractedDocNo  = "ID987654321"
		result.ExtractedExpiry = "2028-06-30"

	case strings.Contains(docType, "DRIVER") || strings.Contains(docType, "LICENSE") || strings.Contains(docType, "LICENCE"):
		result.ExtractedName   = "JOHN MOCK SMITH"
		result.ExtractedDOB    = "1990-01-15"
		result.ExtractedDocNo  = "DL5558881234"
		result.ExtractedExpiry = "2027-01-15"

	default:
		result.ExtractedName   = "JOHN MOCK SMITH"
		result.ExtractedDOB    = "1990-01-15"
		result.ExtractedDocNo  = "UNKNOWN-DOC-001"
		result.ExtractedExpiry = "2029-12-31"
		result.Warnings = append(result.Warnings, "unknown document type — using generic mock data")
	}

	return result, nil
}
