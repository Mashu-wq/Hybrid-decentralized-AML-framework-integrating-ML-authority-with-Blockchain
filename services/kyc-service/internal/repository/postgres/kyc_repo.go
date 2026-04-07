// Package postgres implements the KYC repository interfaces backed by PostgreSQL.
// All queries use parameterized statements — no string interpolation of user data.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fraud-detection/kyc-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KYCRepo implements KYC persistence using a pgx/v5 connection pool.
type KYCRepo struct {
	db *pgxpool.Pool
}

// NewKYCRepo creates a new KYCRepo backed by the given connection pool.
func NewKYCRepo(db *pgxpool.Pool) *KYCRepo {
	return &KYCRepo{db: db}
}

// ---------------------------------------------------------------------------
// Customer write operations
// ---------------------------------------------------------------------------

// CreateCustomer inserts a new customer record and its encrypted PII in a
// single transaction. Returns ErrCustomerAlreadyExists if the identity hash
// is already present.
func (r *KYCRepo) CreateCustomer(ctx context.Context, customer *domain.Customer, pii *domain.EncryptedPII) error {
	const insertCustomer = `
		INSERT INTO kyc.kyc_customers (
			id, identity_hash, kyc_status, risk_level,
			document_type, country_of_issue, nationality,
			city, country_code, postal_code,
			occupation, employer, source_of_funds, expected_monthly_volume,
			liveness_passed, face_match_score, ocr_confidence,
			verifier_id, rejection_reason, blockchain_tx_id, reviewed_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17,
			$18, $19, $20, $21,
			$22, $23
		)
	`
	const insertPII = `
		INSERT INTO kyc.kyc_pii (
			customer_id, full_name_enc, date_of_birth_enc,
			address_line1_enc, address_line2_enc, email_enc,
			phone_number_enc, document_number_enc, expiry_date_enc,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
	`

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	_, err = tx.Exec(ctx, insertCustomer,
		customer.ID,
		customer.IdentityHash,
		string(customer.KYCStatus),
		string(customer.RiskLevel),
		customer.DocumentType,
		customer.CountryOfIssue,
		customer.Nationality,
		customer.City,
		customer.CountryCode,
		customer.PostalCode,
		customer.Occupation,
		customer.Employer,
		customer.SourceOfFunds,
		customer.ExpectedMonthlyVolume,
		customer.LivenessPassed,
		customer.FaceMatchScore,
		customer.OCRConfidence,
		nilIfEmpty(customer.VerifierID),
		nilIfEmpty(customer.RejectionReason),
		nilIfEmpty(customer.BlockchainTxID),
		customer.ReviewedAt,
		now,
		now,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return domain.NewKYCError(domain.ErrCustomerAlreadyExists, "customer with this identity already exists")
		}
		return fmt.Errorf("insert customer: %w", err)
	}

	_, err = tx.Exec(ctx, insertPII,
		pii.CustomerID,
		pii.FullNameEnc,
		pii.DateOfBirthEnc,
		pii.AddressLine1Enc,
		pii.AddressLine2Enc,
		pii.EmailEnc,
		pii.PhoneNumberEnc,
		pii.DocumentNumberEnc,
		pii.ExpiryDateEnc,
	)
	if err != nil {
		return fmt.Errorf("insert encrypted PII: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	customer.CreatedAt = now
	customer.UpdatedAt = now
	return nil
}

// UpdateCustomer persists all mutable fields of a customer record.
func (r *KYCRepo) UpdateCustomer(ctx context.Context, customer *domain.Customer) error {
	const q = `
		UPDATE kyc.kyc_customers SET
			kyc_status             = $2,
			risk_level             = $3,
			document_type          = $4,
			country_of_issue       = $5,
			nationality            = $6,
			city                   = $7,
			country_code           = $8,
			postal_code            = $9,
			occupation             = $10,
			employer               = $11,
			source_of_funds        = $12,
			expected_monthly_volume = $13,
			liveness_passed        = $14,
			face_match_score       = $15,
			ocr_confidence         = $16,
			verifier_id            = $17,
			rejection_reason       = $18,
			blockchain_tx_id       = $19,
			reviewed_at            = $20,
			updated_at             = NOW()
		WHERE id = $1
	`
	tag, err := r.db.Exec(ctx, q,
		customer.ID,
		string(customer.KYCStatus),
		string(customer.RiskLevel),
		customer.DocumentType,
		customer.CountryOfIssue,
		customer.Nationality,
		customer.City,
		customer.CountryCode,
		customer.PostalCode,
		customer.Occupation,
		customer.Employer,
		customer.SourceOfFunds,
		customer.ExpectedMonthlyVolume,
		customer.LivenessPassed,
		customer.FaceMatchScore,
		customer.OCRConfidence,
		nilIfEmpty(customer.VerifierID),
		nilIfEmpty(customer.RejectionReason),
		nilIfEmpty(customer.BlockchainTxID),
		customer.ReviewedAt,
	)
	if err != nil {
		return fmt.Errorf("update customer %s: %w", customer.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return domain.NewKYCError(domain.ErrCustomerNotFound, "customer not found")
	}
	return nil
}

// UpdateCustomerStatus updates the KYC status, risk level, and review metadata
// atomically. This is a targeted update used by the status-change workflow.
func (r *KYCRepo) UpdateCustomerStatus(
	ctx context.Context,
	customerID string,
	status domain.KYCStatus,
	riskLevel domain.RiskLevel,
	reason, verifierID, blockchainTxID string,
) error {
	const q = `
		UPDATE kyc.kyc_customers SET
			kyc_status       = $2,
			risk_level       = $3,
			rejection_reason = $4,
			verifier_id      = $5,
			blockchain_tx_id = $6,
			reviewed_at      = NOW(),
			updated_at       = NOW()
		WHERE id = $1
	`
	tag, err := r.db.Exec(ctx, q,
		customerID,
		string(status),
		string(riskLevel),
		nilIfEmpty(reason),
		nilIfEmpty(verifierID),
		nilIfEmpty(blockchainTxID),
	)
	if err != nil {
		return fmt.Errorf("update customer status %s: %w", customerID, err)
	}
	if tag.RowsAffected() == 0 {
		return domain.NewKYCError(domain.ErrCustomerNotFound, "customer not found")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Customer read operations
// ---------------------------------------------------------------------------

// GetCustomerByID retrieves a customer by their UUID primary key.
func (r *KYCRepo) GetCustomerByID(ctx context.Context, id string) (*domain.Customer, error) {
	const q = `
		SELECT id, identity_hash, kyc_status, risk_level,
		       document_type, country_of_issue, nationality,
		       city, country_code, postal_code,
		       occupation, employer, source_of_funds, expected_monthly_volume,
		       liveness_passed, face_match_score, ocr_confidence,
		       verifier_id, rejection_reason, blockchain_tx_id, reviewed_at,
		       created_at, updated_at
		FROM kyc.kyc_customers
		WHERE id = $1
	`
	return r.scanCustomer(r.db.QueryRow(ctx, q, id))
}

// GetCustomerByIdentityHash retrieves a customer by their identity hash.
// Returns nil, nil when no matching customer exists (used for duplicate checks).
func (r *KYCRepo) GetCustomerByIdentityHash(ctx context.Context, hash string) (*domain.Customer, error) {
	const q = `
		SELECT id, identity_hash, kyc_status, risk_level,
		       document_type, country_of_issue, nationality,
		       city, country_code, postal_code,
		       occupation, employer, source_of_funds, expected_monthly_volume,
		       liveness_passed, face_match_score, ocr_confidence,
		       verifier_id, rejection_reason, blockchain_tx_id, reviewed_at,
		       created_at, updated_at
		FROM kyc.kyc_customers
		WHERE identity_hash = $1
	`
	c, err := r.scanCustomer(r.db.QueryRow(ctx, q, hash))
	if err != nil {
		kycErr, ok := err.(*domain.KYCError)
		if ok && kycErr.Code == domain.ErrCustomerNotFound {
			return nil, nil
		}
		return nil, err
	}
	return c, nil
}

// ListByStatus returns a paginated list of customers filtered by KYC status
// and optionally by country code. Returns the total count for pagination.
func (r *KYCRepo) ListByStatus(
	ctx context.Context,
	status domain.KYCStatus,
	countryCode string,
	limit, offset int,
) ([]*domain.Customer, int, error) {
	baseWhere := "WHERE kyc_status = $1"
	args := []interface{}{string(status)}
	argN := 2

	if countryCode != "" {
		baseWhere += fmt.Sprintf(" AND country_code = $%d", argN)
		args = append(args, countryCode)
		argN++
	}

	countQ := fmt.Sprintf("SELECT COUNT(*) FROM kyc.kyc_customers %s", baseWhere)
	var total int
	if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count customers by status: %w", err)
	}

	dataArgs := append(args, limit, offset)
	dataQ := fmt.Sprintf(`
		SELECT id, identity_hash, kyc_status, risk_level,
		       document_type, country_of_issue, nationality,
		       city, country_code, postal_code,
		       occupation, employer, source_of_funds, expected_monthly_volume,
		       liveness_passed, face_match_score, ocr_confidence,
		       verifier_id, rejection_reason, blockchain_tx_id, reviewed_at,
		       created_at, updated_at
		FROM kyc.kyc_customers
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, baseWhere, argN, argN+1)

	rows, err := r.db.Query(ctx, dataQ, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list customers by status: %w", err)
	}
	defer rows.Close()

	var customers []*domain.Customer
	for rows.Next() {
		c, err := r.scanCustomer(rows)
		if err != nil {
			return nil, 0, err
		}
		customers = append(customers, c)
	}
	return customers, total, rows.Err()
}

// ---------------------------------------------------------------------------
// Encrypted PII operations
// ---------------------------------------------------------------------------

// GetEncryptedPII retrieves the encrypted PII record for a customer.
func (r *KYCRepo) GetEncryptedPII(ctx context.Context, customerID string) (*domain.EncryptedPII, error) {
	const q = `
		SELECT customer_id, full_name_enc, date_of_birth_enc,
		       address_line1_enc, address_line2_enc, email_enc,
		       phone_number_enc, document_number_enc, expiry_date_enc
		FROM kyc.kyc_pii
		WHERE customer_id = $1
	`
	var pii domain.EncryptedPII
	err := r.db.QueryRow(ctx, q, customerID).Scan(
		&pii.CustomerID,
		&pii.FullNameEnc,
		&pii.DateOfBirthEnc,
		&pii.AddressLine1Enc,
		&pii.AddressLine2Enc,
		&pii.EmailEnc,
		&pii.PhoneNumberEnc,
		&pii.DocumentNumberEnc,
		&pii.ExpiryDateEnc,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.NewKYCError(domain.ErrCustomerNotFound, "PII record not found")
	}
	if err != nil {
		return nil, fmt.Errorf("get encrypted PII for customer %s: %w", customerID, err)
	}
	return &pii, nil
}

// ---------------------------------------------------------------------------
// Document operations
// ---------------------------------------------------------------------------

// CreateDocument inserts a new document record.
func (r *KYCRepo) CreateDocument(ctx context.Context, doc *domain.Document) error {
	const q = `
		INSERT INTO kyc.kyc_documents (
			id, customer_id, document_type, s3_key, content_type,
			is_front, ocr_completed, ocr_confidence, ocr_result, status,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
	`
	ocrJSON, err := marshalOCRResult(doc.OCRResult)
	if err != nil {
		return fmt.Errorf("marshal OCR result: %w", err)
	}

	now := time.Now().UTC()
	_, err = r.db.Exec(ctx, q,
		doc.ID,
		doc.CustomerID,
		doc.DocumentType,
		doc.S3Key,
		doc.ContentType,
		doc.IsFront,
		doc.OCRCompleted,
		doc.OCRConfidence,
		ocrJSON,
		doc.Status,
	)
	if err != nil {
		return fmt.Errorf("create document: %w", err)
	}
	doc.CreatedAt = now
	doc.UpdatedAt = now
	return nil
}

// GetDocument retrieves a document record by its ID.
func (r *KYCRepo) GetDocument(ctx context.Context, docID string) (*domain.Document, error) {
	const q = `
		SELECT id, customer_id, document_type, s3_key, content_type,
		       is_front, ocr_completed, ocr_confidence, ocr_result, status,
		       created_at, updated_at
		FROM kyc.kyc_documents
		WHERE id = $1
	`
	return r.scanDocument(r.db.QueryRow(ctx, q, docID))
}

// ListDocuments returns all documents for a given customer.
func (r *KYCRepo) ListDocuments(ctx context.Context, customerID string) ([]*domain.Document, error) {
	const q = `
		SELECT id, customer_id, document_type, s3_key, content_type,
		       is_front, ocr_completed, ocr_confidence, ocr_result, status,
		       created_at, updated_at
		FROM kyc.kyc_documents
		WHERE customer_id = $1
		ORDER BY created_at ASC
	`
	rows, err := r.db.Query(ctx, q, customerID)
	if err != nil {
		return nil, fmt.Errorf("list documents: %w", err)
	}
	defer rows.Close()

	var docs []*domain.Document
	for rows.Next() {
		d, err := r.scanDocument(rows)
		if err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, rows.Err()
}

// UpdateDocument persists OCR results and status changes for a document.
func (r *KYCRepo) UpdateDocument(ctx context.Context, doc *domain.Document) error {
	const q = `
		UPDATE kyc.kyc_documents SET
			ocr_completed  = $2,
			ocr_confidence = $3,
			ocr_result     = $4,
			status         = $5,
			updated_at     = NOW()
		WHERE id = $1
	`
	ocrJSON, err := marshalOCRResult(doc.OCRResult)
	if err != nil {
		return fmt.Errorf("marshal OCR result: %w", err)
	}

	tag, err := r.db.Exec(ctx, q,
		doc.ID,
		doc.OCRCompleted,
		doc.OCRConfidence,
		ocrJSON,
		doc.Status,
	)
	if err != nil {
		return fmt.Errorf("update document %s: %w", doc.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return domain.NewKYCError(domain.ErrDocumentNotFound, "document not found")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

// LogAuditEvent persists a compliance audit event. Failures are non-fatal to
// the primary operation but should be logged by the caller.
func (r *KYCRepo) LogAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	const q = `
		INSERT INTO kyc.kyc_audit_events (
			customer_id, event_type, actor_id, reason, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err = r.db.Exec(ctx, q,
		nilIfEmpty(event.CustomerID),
		event.EventType,
		nilIfEmpty(event.ActorID),
		nilIfEmpty(event.Reason),
		metaJSON,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("log audit event: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// pgxRowScanner is satisfied by both pgx.Row and pgx.Rows.
type pgxRowScanner interface {
	Scan(dest ...interface{}) error
}

func (r *KYCRepo) scanCustomer(row pgxRowScanner) (*domain.Customer, error) {
	var c domain.Customer
	var kycStatus, riskLevel string
	var verifierID, rejectionReason, blockchainTxID *string
	var reviewedAt *time.Time

	err := row.Scan(
		&c.ID,
		&c.IdentityHash,
		&kycStatus,
		&riskLevel,
		&c.DocumentType,
		&c.CountryOfIssue,
		&c.Nationality,
		&c.City,
		&c.CountryCode,
		&c.PostalCode,
		&c.Occupation,
		&c.Employer,
		&c.SourceOfFunds,
		&c.ExpectedMonthlyVolume,
		&c.LivenessPassed,
		&c.FaceMatchScore,
		&c.OCRConfidence,
		&verifierID,
		&rejectionReason,
		&blockchainTxID,
		&reviewedAt,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.NewKYCError(domain.ErrCustomerNotFound, "customer not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scan customer: %w", err)
	}

	c.KYCStatus = domain.KYCStatus(kycStatus)
	c.RiskLevel = domain.RiskLevel(riskLevel)
	if verifierID != nil {
		c.VerifierID = *verifierID
	}
	if rejectionReason != nil {
		c.RejectionReason = *rejectionReason
	}
	if blockchainTxID != nil {
		c.BlockchainTxID = *blockchainTxID
	}
	c.ReviewedAt = reviewedAt
	return &c, nil
}

func (r *KYCRepo) scanDocument(row pgxRowScanner) (*domain.Document, error) {
	var doc domain.Document
	var ocrJSON []byte

	err := row.Scan(
		&doc.ID,
		&doc.CustomerID,
		&doc.DocumentType,
		&doc.S3Key,
		&doc.ContentType,
		&doc.IsFront,
		&doc.OCRCompleted,
		&doc.OCRConfidence,
		&ocrJSON,
		&doc.Status,
		&doc.CreatedAt,
		&doc.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.NewKYCError(domain.ErrDocumentNotFound, "document not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scan document: %w", err)
	}

	if len(ocrJSON) > 0 {
		var ocr domain.OCRResult
		if err := json.Unmarshal(ocrJSON, &ocr); err != nil {
			return nil, fmt.Errorf("unmarshal OCR result: %w", err)
		}
		doc.OCRResult = &ocr
	}
	return &doc, nil
}

func marshalOCRResult(ocr *domain.OCRResult) ([]byte, error) {
	if ocr == nil {
		return []byte("{}"), nil
	}

	// Never persist extracted plaintext PII from OCR results.
	sanitized := domain.OCRResult{
		Success:     ocr.Success,
		Confidence:  ocr.Confidence,
		ExpiryValid: ocr.ExpiryValid,
		NameMatch:   ocr.NameMatch,
		Warnings:    append([]string(nil), ocr.Warnings...),
	}
	return json.Marshal(sanitized)
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsStr(msg, "unique") || containsStr(msg, "duplicate") || containsStr(msg, "23505")
}

func containsStr(s, substr string) bool {
	if len(substr) == 0 || len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
