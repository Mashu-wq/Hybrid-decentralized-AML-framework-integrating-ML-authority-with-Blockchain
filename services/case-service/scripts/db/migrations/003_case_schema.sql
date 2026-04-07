-- ============================================================================
-- Migration 003: Case Management Service schema
-- ============================================================================
-- Run against the fraud_detection PostgreSQL database.
-- Requires pgcrypto for gen_random_uuid() (enabled in migration 001).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- investigation_cases — core case lifecycle table
-- ============================================================================
CREATE TABLE IF NOT EXISTS investigation_cases (
    case_id             TEXT        PRIMARY KEY,
    alert_id            TEXT        NOT NULL UNIQUE, -- one case per alert
    customer_id         TEXT        NOT NULL,
    tx_hash             TEXT        NOT NULL,
    title               TEXT        NOT NULL DEFAULT '',
    description         TEXT        NOT NULL DEFAULT '',

    -- Lifecycle
    status              TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','IN_REVIEW','PENDING_SAR','CLOSED','ESCALATED')),

    -- Priority mirrors alert priority: 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    priority            SMALLINT    NOT NULL DEFAULT 1 CHECK (priority BETWEEN 1 AND 4),

    -- Assignment
    assignee_id         TEXT,
    assigned_at         TIMESTAMPTZ,

    -- ML metadata (from originating alert)
    fraud_probability   DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0,

    -- SAR tracking
    sar_required        BOOLEAN     NOT NULL DEFAULT FALSE,
    sar_s3_key          TEXT        NOT NULL DEFAULT '',
    sar_generated_at    TIMESTAMPTZ,

    -- Blockchain audit trail
    blockchain_tx_id    TEXT        NOT NULL DEFAULT '',

    -- Resolution
    resolution_summary  TEXT        NOT NULL DEFAULT '',
    closed_at           TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE investigation_cases IS 'Investigation case lifecycle — auto-created from HIGH/CRITICAL fraud alerts';
COMMENT ON COLUMN investigation_cases.alert_id IS 'UNIQUE: enforces one case per alert (idempotent auto-creation)';
COMMENT ON COLUMN investigation_cases.priority IS '1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL — mirrors alert priority';
COMMENT ON COLUMN investigation_cases.sar_required IS 'Set TRUE when fraud_probability >= SAR threshold (default 0.85)';

-- ============================================================================
-- Indexes on investigation_cases
-- ============================================================================

-- Customer history
CREATE INDEX IF NOT EXISTS idx_cases_customer_time
    ON investigation_cases (customer_id, created_at DESC);

-- Status + priority (investigator dashboard)
CREATE INDEX IF NOT EXISTS idx_cases_status_priority
    ON investigation_cases (status, priority DESC, created_at DESC);

-- Open cases by assignee (investigator workload)
CREATE INDEX IF NOT EXISTS idx_cases_assignee
    ON investigation_cases (assignee_id, status)
    WHERE assignee_id IS NOT NULL;

-- SAR queue
CREATE INDEX IF NOT EXISTS idx_cases_sar_queue
    ON investigation_cases (priority DESC, created_at)
    WHERE status = 'PENDING_SAR' AND sar_s3_key = '';

-- Fraud probability (analytics)
CREATE INDEX IF NOT EXISTS idx_cases_fraud_prob
    ON investigation_cases (fraud_probability DESC);

-- ============================================================================
-- case_evidence — evidence attachments with S3 references
-- ============================================================================
CREATE TABLE IF NOT EXISTS case_evidence (
    evidence_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         TEXT        NOT NULL REFERENCES investigation_cases(case_id) ON DELETE CASCADE,
    uploaded_by     TEXT        NOT NULL,
    file_name       TEXT        NOT NULL,
    file_size       BIGINT      NOT NULL DEFAULT 0,
    content_type    TEXT        NOT NULL DEFAULT 'application/octet-stream',
    s3_key          TEXT        NOT NULL,
    evidence_type   TEXT        NOT NULL DEFAULT 'OTHER'
                        CHECK (evidence_type IN ('DOCUMENT','SCREENSHOT','TRANSACTION','COMMUNICATION','OTHER')),
    notes           TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE case_evidence IS 'Evidence files referenced by S3 key; pre-signed URLs generated on demand';

CREATE INDEX IF NOT EXISTS idx_evidence_case
    ON case_evidence (case_id, created_at DESC);

-- ============================================================================
-- case_actions — immutable investigator action audit trail
-- ============================================================================
CREATE TABLE IF NOT EXISTS case_actions (
    action_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         TEXT        NOT NULL REFERENCES investigation_cases(case_id),
    investigator_id TEXT        NOT NULL,
    action          TEXT        NOT NULL, -- STATUS_CHANGED, EVIDENCE_ADDED, ASSIGNED, SAR_GENERATED, NOTE_ADDED
    notes           TEXT        NOT NULL DEFAULT '',
    blockchain_tx_id TEXT       NOT NULL DEFAULT '',
    performed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE case_actions IS 'Immutable audit trail of every investigator action; mirrored to Hyperledger Fabric';

CREATE INDEX IF NOT EXISTS idx_case_actions_case
    ON case_actions (case_id, performed_at DESC);

CREATE INDEX IF NOT EXISTS idx_case_actions_investigator
    ON case_actions (investigator_id, performed_at DESC);

-- ============================================================================
-- Trigger: auto-update updated_at on investigation_cases
-- ============================================================================
CREATE OR REPLACE FUNCTION update_case_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_case_updated_at ON investigation_cases;
CREATE TRIGGER trg_case_updated_at
    BEFORE UPDATE ON investigation_cases
    FOR EACH ROW EXECUTE FUNCTION update_case_updated_at();
