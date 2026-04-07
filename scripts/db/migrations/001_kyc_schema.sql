-- ============================================================================
-- Migration: 001_kyc_schema.sql
-- Description: Creates the KYC service schema with customers, PII, documents,
--              and audit event tables.
-- ============================================================================

BEGIN;

-- Create a dedicated schema for KYC data.
CREATE SCHEMA IF NOT EXISTS kyc;

-- ============================================================================
-- kyc_customers — non-PII KYC profile data
-- ============================================================================
CREATE TABLE kyc.kyc_customers (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_hash           VARCHAR(128) NOT NULL UNIQUE,         -- HMAC hash, safe to store plaintext
    kyc_status              VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    risk_level              VARCHAR(32)  NOT NULL DEFAULT 'UNSPECIFIED',

    -- Document metadata (non-PII classification only)
    document_type           VARCHAR(64),
    country_of_issue        CHAR(2),
    nationality             CHAR(2),

    -- Address classification (city/country — not PII)
    city                    VARCHAR(128),
    country_code            CHAR(2),
    postal_code             VARCHAR(32),

    -- Financial profile
    occupation              VARCHAR(128),
    employer                VARCHAR(256),
    source_of_funds         VARCHAR(64),
    expected_monthly_volume DECIMAL(15,2),

    -- Biometric and OCR scores
    liveness_passed         BOOLEAN      NOT NULL DEFAULT FALSE,
    face_match_score        DECIMAL(5,4) NOT NULL DEFAULT 0,
    ocr_confidence          DECIMAL(5,4) NOT NULL DEFAULT 0,

    -- Review metadata
    verifier_id             UUID,
    rejection_reason        TEXT,
    blockchain_tx_id        VARCHAR(128),
    reviewed_at             TIMESTAMPTZ,

    -- Timestamps
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_kyc_status   CHECK (kyc_status   IN ('PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED')),
    CONSTRAINT chk_risk_level   CHECK (risk_level   IN ('UNSPECIFIED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_face_score   CHECK (face_match_score BETWEEN 0 AND 1),
    CONSTRAINT chk_ocr_conf     CHECK (ocr_confidence   BETWEEN 0 AND 1)
);

COMMENT ON TABLE kyc.kyc_customers IS
    'Non-PII KYC profile for each onboarded customer. '
    'All PII is stored encrypted in kyc_pii.';
COMMENT ON COLUMN kyc.kyc_customers.identity_hash IS
    'HMAC-derived identity hash used for deduplication. '
    'One-way — cannot be reversed to recover PII.';

-- ============================================================================
-- kyc_pii — Vault Transit ciphertext for all customer PII
-- ============================================================================
CREATE TABLE kyc.kyc_pii (
    customer_id         UUID         PRIMARY KEY
                            REFERENCES kyc.kyc_customers(id) ON DELETE CASCADE,

    -- All fields are Vault Transit ciphertexts. Never decrypt outside of
    -- an explicit, audited GetDecryptedPII call.
    full_name_enc       TEXT         NOT NULL,
    date_of_birth_enc   TEXT         NOT NULL,
    address_line1_enc   TEXT         NOT NULL,
    address_line2_enc   TEXT         NOT NULL DEFAULT '',
    email_enc           TEXT         NOT NULL,
    phone_number_enc    TEXT         NOT NULL,
    document_number_enc TEXT         NOT NULL,
    expiry_date_enc     TEXT         NOT NULL,

    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE kyc.kyc_pii IS
    'Vault Transit ciphertexts for all customer PII. '
    'Never query without an explicit audit justification.';

-- ============================================================================
-- kyc_documents — document submission tracking
-- ============================================================================
CREATE TABLE kyc.kyc_documents (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     UUID         NOT NULL REFERENCES kyc.kyc_customers(id) ON DELETE CASCADE,
    document_type   VARCHAR(64)  NOT NULL,
    s3_key          TEXT         NOT NULL,
    content_type    VARCHAR(128) NOT NULL DEFAULT 'image/jpeg',
    is_front        BOOLEAN      NOT NULL DEFAULT TRUE,

    -- OCR state
    ocr_completed   BOOLEAN      NOT NULL DEFAULT FALSE,
    ocr_confidence  DECIMAL(5,4) NOT NULL DEFAULT 0,
    ocr_result      JSONB        NOT NULL DEFAULT '{}',

    -- Processing status
    status          VARCHAR(32)  NOT NULL DEFAULT 'PROCESSING',

    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_doc_status CHECK (status IN ('PROCESSING', 'COMPLETED', 'FAILED'))
);

COMMENT ON TABLE kyc.kyc_documents IS
    'Identity document submissions and their OCR processing state.';
COMMENT ON COLUMN kyc.kyc_documents.ocr_result IS
    'JSONB blob of extracted fields. Extracted PII fields (name, DOB, doc number) '
    'are transient — they should not be persisted in plaintext here after processing.';

-- ============================================================================
-- kyc_audit_events — compliance audit trail
-- ============================================================================
CREATE TABLE kyc.kyc_audit_events (
    id          BIGSERIAL    PRIMARY KEY,
    customer_id UUID         REFERENCES kyc.kyc_customers(id) ON DELETE SET NULL,
    event_type  VARCHAR(64)  NOT NULL,
    actor_id    UUID,
    reason      TEXT,
    metadata    JSONB        NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE kyc.kyc_audit_events IS
    'Immutable audit trail for all privileged KYC actions. '
    'Rows are never updated or deleted.';

-- ============================================================================
-- Indexes for common query patterns
-- ============================================================================

-- Status-based list queries (primary use case for compliance queues).
CREATE INDEX idx_kyc_customers_status
    ON kyc.kyc_customers(kyc_status);

-- Country-based filtering (jurisdiction reporting).
CREATE INDEX idx_kyc_customers_country
    ON kyc.kyc_customers(country_code);

-- Combined status + country (list_by_status RPC with country filter).
CREATE INDEX idx_kyc_customers_status_country
    ON kyc.kyc_customers(kyc_status, country_code);

-- Created-at ordering for pagination.
CREATE INDEX idx_kyc_customers_created_at
    ON kyc.kyc_customers(created_at DESC);

-- Document lookup by customer.
CREATE INDEX idx_kyc_documents_customer
    ON kyc.kyc_documents(customer_id);

-- Audit event lookup by customer, descending (most recent first).
CREATE INDEX idx_kyc_audit_customer
    ON kyc.kyc_audit_events(customer_id, created_at DESC);

-- Audit event lookup by type (compliance queries).
CREATE INDEX idx_kyc_audit_event_type
    ON kyc.kyc_audit_events(event_type, created_at DESC);

COMMIT;
