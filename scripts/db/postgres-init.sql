-- =============================================================================
-- FRAUD DETECTION SYSTEM — PostgreSQL Initialization
-- Runs once on first container start.
-- Extensions, databases, schemas created here.
-- Service-specific tables are created by migrations (migrate tool per service).
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- gen_random_uuid(), crypt(), AES
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- trigram indexes for text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";      -- GIN indexes on scalar types

-- Set timezone
SET timezone = 'UTC';

-- =============================================================================
-- SCHEMAS (one per logical domain)
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS iam;           -- identity & access management
CREATE SCHEMA IF NOT EXISTS kyc;           -- customer onboarding
CREATE SCHEMA IF NOT EXISTS alerts;        -- fraud alerts
CREATE SCHEMA IF NOT EXISTS cases;         -- investigation cases
CREATE SCHEMA IF NOT EXISTS analytics;    -- metrics and reporting
CREATE SCHEMA IF NOT EXISTS audit;         -- audit log

-- =============================================================================
-- IAM SCHEMA — users, roles, permissions, sessions
-- =============================================================================

CREATE TABLE IF NOT EXISTS iam.roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(50) NOT NULL UNIQUE,  -- ADMIN, ANALYST, INVESTIGATOR, AUDITOR, API_CLIENT
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS iam.permissions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(100) NOT NULL,   -- e.g. "alerts", "cases", "kyc"
    action      VARCHAR(50)  NOT NULL,   -- e.g. "read", "write", "delete"
    description TEXT,
    UNIQUE (resource, action)
);

CREATE TABLE IF NOT EXISTS iam.role_permissions (
    role_id       UUID NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES iam.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS iam.users (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             VARCHAR(255) NOT NULL UNIQUE,
    password_hash     TEXT        NOT NULL,        -- bcrypt cost 12
    role_id           UUID        NOT NULL REFERENCES iam.roles(id),
    mfa_enabled       BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_secret        TEXT,                          -- TOTP secret (encrypted at app layer)
    mfa_backup_codes  TEXT[],                        -- hashed backup codes
    active            BOOLEAN     NOT NULL DEFAULT TRUE,
    failed_attempts   INT         NOT NULL DEFAULT 0,
    locked_until      TIMESTAMPTZ,
    last_login_at     TIMESTAMPTZ,
    last_login_ip     INET,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON iam.users(email);
CREATE INDEX IF NOT EXISTS idx_users_role_id ON iam.users(role_id);

CREATE TABLE IF NOT EXISTS iam.refresh_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,   -- SHA-256 of the raw token
    device_id   VARCHAR(255),
    ip_address  INET,
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON iam.refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON iam.refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS iam.audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        REFERENCES iam.users(id),
    event_type  VARCHAR(100) NOT NULL,   -- LOGIN_SUCCESS, LOGIN_FAILURE, MFA_ENABLED, etc.
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB       DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_iam_audit_user ON iam.audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iam_audit_event ON iam.audit_log(event_type, created_at DESC);

-- =============================================================================
-- KYC SCHEMA — customer KYC records (PII encrypted at application layer)
-- =============================================================================

CREATE TABLE IF NOT EXISTS kyc.records (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_hash     VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256(PII) — stored in blockchain too
    -- PII fields encrypted by Encryption Service before storage:
    encrypted_pii     BYTEA,             -- AES-256-GCM ciphertext of full PII JSON
    pii_key_version   INT  NOT NULL DEFAULT 1,
    kyc_status        VARCHAR(20) NOT NULL DEFAULT 'PENDING',  -- PENDING,APPROVED,REJECTED,SUSPENDED
    risk_level        VARCHAR(10) NOT NULL DEFAULT 'UNKNOWN',  -- LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN
    document_type     VARCHAR(50),       -- PASSPORT, DRIVING_LICENSE, NATIONAL_ID
    country_of_issue  CHAR(2),           -- ISO 3166-1 alpha-2
    liveness_passed   BOOLEAN,
    face_match_score  DECIMAL(5,4),      -- 0.0000 – 1.0000
    ocr_confidence    DECIMAL(5,4),
    verifier_id       UUID REFERENCES iam.users(id),
    reviewed_at       TIMESTAMPTZ,
    rejection_reason  TEXT,
    blockchain_tx_id  VARCHAR(255),      -- Fabric transaction ID after registration
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_kyc_status CHECK (kyc_status IN ('PENDING','APPROVED','REJECTED','SUSPENDED')),
    CONSTRAINT chk_risk_level CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'))
);

CREATE INDEX IF NOT EXISTS idx_kyc_status      ON kyc.records(kyc_status);
CREATE INDEX IF NOT EXISTS idx_kyc_risk        ON kyc.records(risk_level);
CREATE INDEX IF NOT EXISTS idx_kyc_created_at  ON kyc.records(created_at DESC);

CREATE TABLE IF NOT EXISTS kyc.documents (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kyc_record_id UUID        NOT NULL REFERENCES kyc.records(id) ON DELETE CASCADE,
    document_type VARCHAR(50) NOT NULL,
    s3_key        TEXT        NOT NULL,  -- S3 object key (encrypted file)
    ocr_result    JSONB,                 -- Textract output (PII scrubbed)
    uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- ALERTS SCHEMA — fraud alert lifecycle
-- =============================================================================

CREATE TABLE IF NOT EXISTS alerts.alerts (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id       UUID        NOT NULL REFERENCES kyc.records(id),
    tx_hash           VARCHAR(255) NOT NULL,
    fraud_probability DECIMAL(5,4) NOT NULL,
    risk_score        DECIMAL(6,2) NOT NULL,
    status            VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    priority          VARCHAR(10) NOT NULL,
    model_version     VARCHAR(50) NOT NULL,
    shap_explanation  JSONB,            -- top-5 SHAP feature contributions
    features_snapshot JSONB,            -- feature vector at prediction time
    dedup_hash        VARCHAR(64) UNIQUE,  -- prevents duplicate alerts
    assignee_id       UUID REFERENCES iam.users(id),
    assigned_at       TIMESTAMPTZ,
    resolved_at       TIMESTAMPTZ,
    resolution_notes  TEXT,
    blockchain_tx_id  VARCHAR(255),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_alert_status   CHECK (status   IN ('OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE','ESCALATED')),
    CONSTRAINT chk_alert_priority CHECK (priority IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_customer  ON alerts.alerts(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts.alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_priority  ON alerts.alerts(priority, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_fraud_prob ON alerts.alerts(fraud_probability DESC);

-- Alert notification log
CREATE TABLE IF NOT EXISTS alerts.notifications (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID        NOT NULL REFERENCES alerts.alerts(id),
    channel     VARCHAR(20) NOT NULL,   -- EMAIL, SMS, SLACK, WEBHOOK
    recipient   TEXT        NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'PENDING',  -- PENDING, SENT, FAILED
    sent_at     TIMESTAMPTZ,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- CASES SCHEMA — investigation case management
-- =============================================================================

CREATE TABLE IF NOT EXISTS cases.cases (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        UUID        NOT NULL REFERENCES alerts.alerts(id),
    customer_id     UUID        NOT NULL REFERENCES kyc.records(id),
    status          VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    assigned_to     UUID REFERENCES iam.users(id),
    assigned_at     TIMESTAMPTZ,
    sar_required    BOOLEAN     NOT NULL DEFAULT FALSE,
    sar_filed_at    TIMESTAMPTZ,
    sar_reference   VARCHAR(100),
    closed_at       TIMESTAMPTZ,
    closure_reason  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_case_status CHECK (status IN ('OPEN','IN_REVIEW','PENDING_SAR','CLOSED'))
);

CREATE INDEX IF NOT EXISTS idx_cases_status       ON cases.cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assignee     ON cases.cases(assigned_to);
CREATE INDEX IF NOT EXISTS idx_cases_customer     ON cases.cases(customer_id);
CREATE INDEX IF NOT EXISTS idx_cases_created_at   ON cases.cases(created_at DESC);

CREATE TABLE IF NOT EXISTS cases.evidence (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID        NOT NULL REFERENCES cases.cases(id) ON DELETE CASCADE,
    uploaded_by   UUID        NOT NULL REFERENCES iam.users(id),
    file_name     TEXT        NOT NULL,
    s3_key        TEXT        NOT NULL,
    content_type  VARCHAR(100),
    size_bytes    BIGINT,
    description   TEXT,
    uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases.timeline (
    id            BIGSERIAL   PRIMARY KEY,
    case_id       UUID        NOT NULL REFERENCES cases.cases(id) ON DELETE CASCADE,
    actor_id      UUID        NOT NULL REFERENCES iam.users(id),
    action        VARCHAR(100) NOT NULL,
    description   TEXT,
    metadata      JSONB DEFAULT '{}',
    blockchain_tx VARCHAR(255),   -- Fabric audit-channel TX ID
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_timeline_case ON cases.timeline(case_id, created_at DESC);

-- =============================================================================
-- ANALYTICS SCHEMA — aggregated metrics
-- =============================================================================

CREATE TABLE IF NOT EXISTS analytics.model_metrics (
    id            BIGSERIAL   PRIMARY KEY,
    model_name    VARCHAR(100) NOT NULL,
    model_version VARCHAR(50)  NOT NULL,
    precision_val DECIMAL(6,4),
    recall_val    DECIMAL(6,4),
    f1_score      DECIMAL(6,4),
    auc_roc       DECIMAL(6,4),
    sample_count  INT,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_metrics_name ON analytics.model_metrics(model_name, recorded_at DESC);

CREATE TABLE IF NOT EXISTS analytics.fraud_rate_snapshots (
    id                  BIGSERIAL   PRIMARY KEY,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    total_transactions  BIGINT      NOT NULL DEFAULT 0,
    fraud_detected      BIGINT      NOT NULL DEFAULT 0,
    fraud_rate          DECIMAL(8,6),
    avg_fraud_prob      DECIMAL(5,4),
    alerts_created      INT         NOT NULL DEFAULT 0,
    cases_opened        INT         NOT NULL DEFAULT 0,
    sar_filed           INT         NOT NULL DEFAULT 0,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- UTILITY: updated_at auto-update trigger
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables with updated_at
DO $$
DECLARE
    t record;
BEGIN
    FOR t IN
        SELECT schemaname, tablename
        FROM pg_tables
        WHERE schemaname IN ('iam','kyc','alerts','cases')
          AND tablename NOT IN ('audit_log','notifications','evidence','timeline','documents')
    LOOP
        EXECUTE format(
            'CREATE TRIGGER trg_updated_at BEFORE UPDATE ON %I.%I
             FOR EACH ROW EXECUTE FUNCTION update_updated_at()',
            t.schemaname, t.tablename
        );
    END LOOP;
END;
$$;

-- =============================================================================
-- SEED: Default roles and permissions
-- =============================================================================

-- Roles
INSERT INTO iam.roles (id, name, description) VALUES
    ('00000000-0000-0000-0000-000000000001', 'ADMIN',       'Full system access'),
    ('00000000-0000-0000-0000-000000000002', 'ANALYST',     'View and triage fraud alerts'),
    ('00000000-0000-0000-0000-000000000003', 'INVESTIGATOR','Manage cases, attach evidence'),
    ('00000000-0000-0000-0000-000000000004', 'AUDITOR',     'Read-only audit trail access'),
    ('00000000-0000-0000-0000-000000000005', 'API_CLIENT',  'Machine-to-machine API access')
ON CONFLICT (id) DO NOTHING;

-- Core permissions
INSERT INTO iam.permissions (resource, action) VALUES
    ('alerts', 'read'),   ('alerts', 'write'),   ('alerts', 'delete'),
    ('cases',  'read'),   ('cases',  'write'),   ('cases',  'delete'),
    ('kyc',    'read'),   ('kyc',    'write'),   ('kyc',    'delete'),
    ('users',  'read'),   ('users',  'write'),   ('users',  'delete'),
    ('reports','read'),   ('reports','generate'),
    ('audit',  'read'),
    ('ml',     'predict'),('ml',     'train'),
    ('blockchain', 'read'), ('blockchain', 'write')
ON CONFLICT (resource, action) DO NOTHING;

-- Grant all permissions to ADMIN
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001',
    id
FROM iam.permissions
ON CONFLICT DO NOTHING;

-- ANALYST: read alerts, read kyc, read cases, ml:predict
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', id
FROM iam.permissions
WHERE (resource, action) IN (
    ('alerts','read'), ('cases','read'), ('kyc','read'),
    ('reports','read'), ('ml','predict'), ('blockchain','read')
)
ON CONFLICT DO NOTHING;

-- INVESTIGATOR: alerts+cases read/write, evidence
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', id
FROM iam.permissions
WHERE (resource, action) IN (
    ('alerts','read'), ('alerts','write'),
    ('cases','read'),  ('cases','write'),
    ('kyc','read'), ('reports','read'), ('reports','generate'),
    ('ml','predict'), ('blockchain','read'), ('blockchain','write')
)
ON CONFLICT DO NOTHING;

-- AUDITOR: read-only everything
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004', id
FROM iam.permissions
WHERE action = 'read'
ON CONFLICT DO NOTHING;

SELECT 'Database initialization complete' AS status;
