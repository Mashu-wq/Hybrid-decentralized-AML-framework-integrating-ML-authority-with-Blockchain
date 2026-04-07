-- ============================================================================
-- Migration 002: Alert Service schema
-- ============================================================================
-- Run against the fraud_detection PostgreSQL database.
-- Requires pgcrypto for gen_random_uuid() (enabled in migration 001).

-- Enable pgcrypto if not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- fraud_alerts — core alert lifecycle table
-- ============================================================================
CREATE TABLE IF NOT EXISTS fraud_alerts (
    alert_id               TEXT        PRIMARY KEY,
    customer_id            TEXT        NOT NULL,
    tx_hash                TEXT        NOT NULL,
    fraud_probability      DOUBLE PRECISION NOT NULL,
    risk_score             DOUBLE PRECISION NOT NULL DEFAULT 0,

    -- Priority: 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    priority               SMALLINT    NOT NULL DEFAULT 1 CHECK (priority BETWEEN 1 AND 4),

    -- Lifecycle status
    status                 TEXT        NOT NULL DEFAULT 'OPEN'
                               CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE','ESCALATED')),

    -- ML metadata
    model_version          TEXT        NOT NULL DEFAULT '',
    shap_explanation_json  TEXT        NOT NULL DEFAULT '[]',
    features_snapshot_json TEXT        NOT NULL DEFAULT '{}',

    -- Assignment
    assignee_id            TEXT,
    assigned_at            TIMESTAMPTZ,

    -- Escalation
    escalated_at           TIMESTAMPTZ,

    -- Resolution
    resolved_at            TIMESTAMPTZ,
    resolution_notes       TEXT        NOT NULL DEFAULT '',

    -- Blockchain audit trail
    blockchain_tx_id       TEXT        NOT NULL DEFAULT '',

    -- Deduplication: SHA-256(customer_id || ':' || tx_hash)
    -- UNIQUE ensures idempotency even if Redis dedup cache is cold.
    dedup_hash             TEXT        NOT NULL UNIQUE,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE fraud_alerts IS 'Fraud alert lifecycle — created from alerts.created Kafka topic, managed by Alert Service';
COMMENT ON COLUMN fraud_alerts.dedup_hash IS 'SHA-256(customer_id||":" ||tx_hash) — prevents duplicate alerts for the same transaction';
COMMENT ON COLUMN fraud_alerts.priority IS '1=LOW (<0.5), 2=MEDIUM (0.5–0.7), 3=HIGH (0.7–0.85), 4=CRITICAL (>0.85)';

-- ============================================================================
-- Indexes
-- ============================================================================

-- Customer history (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_alerts_customer_time
    ON fraud_alerts (customer_id, created_at DESC);

-- Status + priority (analyst dashboard default sort)
CREATE INDEX IF NOT EXISTS idx_alerts_status_priority
    ON fraud_alerts (status, priority DESC, created_at DESC);

-- Open + high/critical (escalation scheduler query)
CREATE INDEX IF NOT EXISTS idx_alerts_escalation_candidates
    ON fraud_alerts (priority, created_at)
    WHERE status IN ('OPEN', 'INVESTIGATING') AND escalated_at IS NULL;

-- Assignee workload (investigator dashboard)
CREATE INDEX IF NOT EXISTS idx_alerts_assignee
    ON fraud_alerts (assignee_id, status)
    WHERE assignee_id IS NOT NULL;

-- Fraud probability filter (analytics)
CREATE INDEX IF NOT EXISTS idx_alerts_fraud_prob
    ON fraud_alerts (fraud_probability DESC);

-- ============================================================================
-- alert_notifications — log of all notification attempts
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_notifications (
    notification_id  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id         TEXT        NOT NULL REFERENCES fraud_alerts(alert_id),
    channel          TEXT        NOT NULL CHECK (channel IN ('EMAIL','SMS','SLACK','WEBHOOK')),
    recipient        TEXT        NOT NULL,
    success          BOOLEAN     NOT NULL,
    provider_msg_id  TEXT,        -- SendGrid/Twilio message ID on success
    error_message    TEXT,        -- provider error on failure
    sent_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_alert
    ON alert_notifications (alert_id, sent_at DESC);

-- ============================================================================
-- alert_status_history — immutable audit trail of status changes
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_status_history (
    history_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id     TEXT        NOT NULL REFERENCES fraud_alerts(alert_id),
    from_status  TEXT        NOT NULL,
    to_status    TEXT        NOT NULL,
    changed_by   TEXT        NOT NULL,  -- user_id or "system" (escalation scheduler)
    notes        TEXT        NOT NULL DEFAULT '',
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_history
    ON alert_status_history (alert_id, changed_at DESC);

-- ============================================================================
-- Trigger: auto-update updated_at on fraud_alerts
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_updated_at ON fraud_alerts;
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON fraud_alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
