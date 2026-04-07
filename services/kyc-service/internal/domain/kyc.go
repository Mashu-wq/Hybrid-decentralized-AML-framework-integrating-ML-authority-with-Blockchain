// Package domain defines the core business entities and error types for the KYC service.
// All PII fields are clearly annotated — they must never appear in log output.
package domain

import "time"

// ---------------------------------------------------------------------------
// Status and risk enumerations
// ---------------------------------------------------------------------------

// KYCStatus represents the verification lifecycle state of a customer.
type KYCStatus string

const (
	// KYCStatusPending means the customer has registered but not yet been verified.
	KYCStatusPending KYCStatus = "PENDING"
	// KYCStatusApproved means the customer has passed all KYC checks.
	KYCStatusApproved KYCStatus = "APPROVED"
	// KYCStatusRejected means the customer failed one or more KYC checks.
	KYCStatusRejected KYCStatus = "REJECTED"
	// KYCStatusSuspended means the customer was approved but has been suspended.
	KYCStatusSuspended KYCStatus = "SUSPENDED"
)

// RiskLevel classifies the AML risk associated with a customer.
type RiskLevel string

const (
	// RiskLevelUnspecified is the default zero value.
	RiskLevelUnspecified RiskLevel = "UNSPECIFIED"
	// RiskLevelLow means the customer poses low AML risk.
	RiskLevelLow RiskLevel = "LOW"
	// RiskLevelMedium means the customer poses moderate AML risk.
	RiskLevelMedium RiskLevel = "MEDIUM"
	// RiskLevelHigh means the customer poses elevated AML risk.
	RiskLevelHigh RiskLevel = "HIGH"
	// RiskLevelCritical means the customer poses critical AML risk.
	RiskLevelCritical RiskLevel = "CRITICAL"
)

// ---------------------------------------------------------------------------
// Core domain models
// ---------------------------------------------------------------------------

// Customer represents the non-PII KYC profile of an onboarded customer.
// PII fields (name, DOB, address, etc.) are stored encrypted in EncryptedPII.
type Customer struct {
	ID           string
	IdentityHash string // stable, one-way hash — safe to store/log

	KYCStatus KYCStatus
	RiskLevel RiskLevel

	// Document metadata (non-PII)
	DocumentType   string
	CountryOfIssue string
	Nationality    string

	// Address components (non-PII classification data only)
	City        string
	CountryCode string
	PostalCode  string

	// Financial profile
	Occupation            string
	Employer              string
	SourceOfFunds         string
	ExpectedMonthlyVolume float64

	// Biometric and OCR scores
	LivenessPassed bool
	FaceMatchScore float64
	OCRConfidence  float64

	// Review metadata
	VerifierID      string
	RejectionReason string
	BlockchainTxID  string
	ReviewedAt      *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// EncryptedPII holds Vault Transit ciphertext for all customer PII fields.
// Never decrypt outside of an explicit, audited GetDecryptedPII call.
type EncryptedPII struct {
	CustomerID string

	// All fields below are Vault Transit ciphertexts — DO NOT LOG
	FullNameEnc      string
	DateOfBirthEnc   string
	AddressLine1Enc  string
	AddressLine2Enc  string
	EmailEnc         string
	PhoneNumberEnc   string
	DocumentNumberEnc string
	ExpiryDateEnc    string
}

// Document represents an identity document submitted by a customer.
type Document struct {
	ID           string
	CustomerID   string
	DocumentType string
	S3Key        string
	ContentType  string
	IsFront      bool

	// OCR state
	OCRCompleted  bool
	OCRConfidence float64
	OCRResult     *OCRResult

	Status    string // PROCESSING, COMPLETED, FAILED
	CreatedAt time.Time
	UpdatedAt time.Time
}

// OCRResult contains the text extraction results from AWS Textract.
// Extracted PII fields are transient — never persist them in plaintext.
type OCRResult struct {
	Success    bool
	Confidence float64

	// Extracted fields — DO NOT LOG, DO NOT PERSIST PLAINTEXT
	ExtractedName   string
	ExtractedDOB    string
	ExtractedDocNo  string
	ExtractedExpiry string

	// Derived validation flags (non-PII, safe to log)
	ExpiryValid bool
	NameMatch   bool
	Warnings    []string
}

// FaceVerifyResult carries biometric verification output.
type FaceVerifyResult struct {
	FaceMatch      bool
	MatchScore     float64
	LivenessPassed bool
	LivenessScore  float64
	FailureReason  string
	ModelVersion   string
}

// KYCEvent is published to Kafka for downstream consumers (ML, alert, analytics).
// Contains only non-PII fields.
type KYCEvent struct {
	EventType    string
	CustomerID   string
	IdentityHash string
	KYCStatus    KYCStatus
	RiskLevel    RiskLevel
	CountryCode  string
	DocumentType string
	Timestamp    time.Time
}

// AuditEvent records a privileged action for the compliance audit trail.
type AuditEvent struct {
	CustomerID string
	EventType  string
	ActorID    string
	Reason     string
	Metadata   map[string]string
	CreatedAt  time.Time
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// ErrCode classifies KYC domain errors for gRPC and HTTP mapping.
type ErrCode string

const (
	// ErrCustomerNotFound is returned when a customer ID does not exist.
	ErrCustomerNotFound ErrCode = "CUSTOMER_NOT_FOUND"
	// ErrCustomerAlreadyExists is returned when the identity hash already exists.
	ErrCustomerAlreadyExists ErrCode = "CUSTOMER_ALREADY_EXISTS"
	// ErrDocumentNotFound is returned when a document ID does not exist.
	ErrDocumentNotFound ErrCode = "DOCUMENT_NOT_FOUND"
	// ErrInvalidStatus is returned when a status transition is not allowed.
	ErrInvalidStatus ErrCode = "INVALID_STATUS"
	// ErrPermissionDenied is returned when the caller lacks required permissions.
	ErrPermissionDenied ErrCode = "PERMISSION_DENIED"
	// ErrInternal is returned for unexpected internal failures.
	ErrInternal ErrCode = "INTERNAL"
)

// KYCError is a structured domain error that carries a machine-readable code
// alongside a human-readable message.
type KYCError struct {
	Code    ErrCode
	Message string
}

// Error implements the error interface.
func (e *KYCError) Error() string {
	return string(e.Code) + ": " + e.Message
}

// NewKYCError constructs a KYCError with the given code and message.
func NewKYCError(code ErrCode, message string) *KYCError {
	return &KYCError{Code: code, Message: message}
}
