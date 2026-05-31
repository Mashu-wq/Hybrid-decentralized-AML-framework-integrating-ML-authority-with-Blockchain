-- ============================================================================
-- Migration 004: Analytics Service — reporting views and indexes
-- ============================================================================
-- These views are read-only convenience wrappers used by the Analytics Service.
-- They do not modify the fraud_alerts or investigation_cases base tables.

-- ---------------------------------------------------------------------------
-- Ensure required extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- v_alert_daily_summary — pre-aggregated daily alert counts for fast trending
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_alert_daily_summary AS
SELECT
    date_trunc('day', created_at)::date                     AS alert_date,
    COUNT(*)                                                 AS total_alerts,
    COUNT(*) FILTER (WHERE priority >= 3)                    AS high_critical_count,
    COUNT(*) FILTER (WHERE status = 'RESOLVED')              AS resolved_count,
    COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')        AS false_positive_count,
    COUNT(*) FILTER (WHERE status = 'ESCALATED')             AS escalated_count,
    ROUND(AVG(fraud_probability)::numeric, 4)                AS avg_fraud_probability,
    ROUND(AVG(risk_score)::numeric, 2)                       AS avg_risk_score,
    COUNT(DISTINCT customer_id)                              AS unique_customers
FROM fraud_alerts
GROUP BY 1;

COMMENT ON VIEW v_alert_daily_summary IS 'Daily aggregation of fraud_alerts for the Analytics Service trending queries.';

-- ---------------------------------------------------------------------------
-- v_customer_risk_profile — current risk snapshot per customer
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_customer_risk_profile AS
SELECT
    customer_id,
    COUNT(*)                                                            AS total_alerts,
    COUNT(*) FILTER (WHERE priority >= 3)                               AS high_critical_count,
    ROUND(
        COUNT(*) FILTER (WHERE priority >= 3)::numeric / NULLIF(COUNT(*), 0),
        4)                                                              AS fraud_rate,
    ROUND(AVG(risk_score)::numeric, 2)                                  AS avg_risk_score,
    ROUND(AVG(fraud_probability)::numeric, 4)                           AS avg_fraud_probability,
    MAX(created_at)                                                     AS last_alert_at,
    MIN(created_at)                                                     AS first_alert_at
FROM fraud_alerts
GROUP BY customer_id;

COMMENT ON VIEW v_customer_risk_profile IS 'Aggregated customer risk profile for the Analytics Service top-risky-customers queries.';

-- ---------------------------------------------------------------------------
-- v_model_performance — performance metrics per model version
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_model_performance AS
SELECT
    model_version,
    COUNT(*)                                                            AS total_predictions,
    COUNT(*) FILTER (WHERE status = 'RESOLVED')                         AS true_positives,
    COUNT(*) FILTER (WHERE status = 'FALSE_POSITIVE')                   AS false_positives,
    COUNT(*) FILTER (WHERE status NOT IN ('RESOLVED','FALSE_POSITIVE')) AS unresolved,
    ROUND(
        COUNT(*) FILTER (WHERE status = 'RESOLVED')::numeric /
        NULLIF(COUNT(*) FILTER (WHERE status IN ('RESOLVED','FALSE_POSITIVE')), 0),
        4)                                                              AS precision,
    ROUND(AVG(fraud_probability) FILTER (WHERE status = 'RESOLVED')::numeric, 4) AS avg_prob_tp,
    ROUND(AVG(fraud_probability) FILTER (WHERE status = 'FALSE_POSITIVE')::numeric, 4) AS avg_prob_fp
FROM fraud_alerts
GROUP BY model_version;

COMMENT ON VIEW v_model_performance IS 'Model performance metrics per model version for Analytics Service audits.';

-- ---------------------------------------------------------------------------
-- Additional indexes that help analytics query patterns (if not already exist)
-- ---------------------------------------------------------------------------

-- Analytics time-range scans (GetFraudTrends, GetAlertMetrics)
CREATE INDEX IF NOT EXISTS idx_alerts_created_at_analytics
    ON fraud_alerts (created_at DESC)
    INCLUDE (priority, status, fraud_probability, risk_score, customer_id);

-- Model performance queries
CREATE INDEX IF NOT EXISTS idx_alerts_model_version
    ON fraud_alerts (model_version, created_at DESC)
    INCLUDE (status, fraud_probability);

-- Customer risk profile queries
CREATE INDEX IF NOT EXISTS idx_alerts_customer_priority
    ON fraud_alerts (customer_id, priority, created_at DESC);
