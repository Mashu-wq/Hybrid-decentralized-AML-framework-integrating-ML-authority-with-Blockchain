#!/usr/bin/env bash
# =============================================================================
# FRAUD DETECTION SYSTEM — Seed Development Data
# =============================================================================
# Seeds IAM users, KYC customers, alerts, cases (PostgreSQL) and sample
# transactions (MongoDB). Idempotent: safe to re-run (ON CONFLICT DO NOTHING).
#
# Tables live in per-service schemas (iam.*, kyc.*, alerts.*, cases.*) and all
# primary keys are UUIDs. Roles are pre-seeded by scripts/db/postgres-init.sql
# with fixed UUIDs; users reference them by name lookup.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[SEED]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }

# --- Load env ---
if [ -f ".env" ]; then set -a && source .env && set +a; fi

PG_CONTAINER="${PG_CONTAINER:-fds-postgres}"
PGUSER="${POSTGRES_USER:-fraud_user}"
PGDB="${POSTGRES_DB:-fraud_detection}"

# Run psql inside the container (no host psql client required).
psql_run() {
    docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDB" -v ON_ERROR_STOP=1 "$@"
}

# Default seed password for ALL users below: FraudOps@2026
# bcrypt cost 12 (matches iam-service BCRYPT_COST). Single-quoted heredocs keep
# the '$' characters in the hash literal.
SEED_PASSWORD="FraudOps@2026"

log_info "Seeding IAM users (roles are pre-seeded by postgres-init.sql)..."
psql_run << 'SQL'
-- Admin / analyst / investigator / auditor. role_id resolved by role name.
INSERT INTO iam.users (id, email, password_hash, role_id, mfa_enabled, active) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'admin@fraud.local',
     '$2a$12$gZsW6zoCj5J0O/UEuWTpp.NDxx7l4VqSPq9f7hI/7iKsM0kDkmNzm',
     (SELECT id FROM iam.roles WHERE name='ADMIN'),        false, true),
    ('a0000000-0000-0000-0000-000000000002', 'analyst@fraud.local',
     '$2a$12$gZsW6zoCj5J0O/UEuWTpp.NDxx7l4VqSPq9f7hI/7iKsM0kDkmNzm',
     (SELECT id FROM iam.roles WHERE name='ANALYST'),      false, true),
    ('a0000000-0000-0000-0000-000000000003', 'investigator@fraud.local',
     '$2a$12$gZsW6zoCj5J0O/UEuWTpp.NDxx7l4VqSPq9f7hI/7iKsM0kDkmNzm',
     (SELECT id FROM iam.roles WHERE name='INVESTIGATOR'), false, true),
    ('a0000000-0000-0000-0000-000000000004', 'auditor@fraud.local',
     '$2a$12$gZsW6zoCj5J0O/UEuWTpp.NDxx7l4VqSPq9f7hI/7iKsM0kDkmNzm',
     (SELECT id FROM iam.roles WHERE name='AUDITOR'),      false, true)
ON CONFLICT (email) DO NOTHING;

SELECT 'IAM users: ' || count(*) AS status FROM iam.users;
SQL
log_success "IAM users seeded"

log_info "Seeding KYC customers..."
psql_run << 'SQL'
INSERT INTO kyc.kyc_customers
    (id, identity_hash, kyc_status, risk_level, document_type, country_of_issue,
     nationality, country_code, verifier_id) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'sha256:aabbcc001', 'APPROVED', 'LOW',
     'PASSPORT', 'US', 'US', 'US', 'a0000000-0000-0000-0000-000000000002'),
    ('c0000000-0000-0000-0000-000000000002', 'sha256:aabbcc002', 'APPROVED', 'MEDIUM',
     'PASSPORT', 'GB', 'GB', 'GB', 'a0000000-0000-0000-0000-000000000002'),
    ('c0000000-0000-0000-0000-000000000003', 'sha256:aabbcc003', 'PENDING', 'HIGH',
     'NATIONAL_ID', 'NG', 'NG', 'NG', NULL),
    ('c0000000-0000-0000-0000-000000000004', 'sha256:aabbcc004', 'REJECTED', 'HIGH',
     'PASSPORT', 'RU', 'RU', 'RU', 'a0000000-0000-0000-0000-000000000002'),
    ('c0000000-0000-0000-0000-000000000005', 'sha256:aabbcc005', 'APPROVED', 'CRITICAL',
     'PASSPORT', 'KY', 'KY', 'KY', 'a0000000-0000-0000-0000-000000000002')
ON CONFLICT (id) DO NOTHING;

SELECT 'KYC customers: ' || count(*) AS status FROM kyc.kyc_customers;
SQL
log_success "KYC customers seeded"

log_info "Seeding sample alerts..."
psql_run << 'SQL'
INSERT INTO alerts.alerts
    (id, customer_id, tx_hash, fraud_probability, risk_score, status, priority,
     model_version, assignee_id, created_at, updated_at) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000001',
     'tx:hash:001', 0.9200, 95.0, 'OPEN',          'CRITICAL', '1.0.0', NULL,
     NOW() - INTERVAL '2 hours', NOW()),
    ('b0000000-0000-0000-0000-000000000002', 'c0000000-0000-0000-0000-000000000002',
     'tx:hash:002', 0.7800, 82.0, 'INVESTIGATING', 'HIGH',     '1.0.0',
     'a0000000-0000-0000-0000-000000000003', NOW() - INTERVAL '4 hours', NOW()),
    ('b0000000-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-000000000001',
     'tx:hash:003', 0.6100, 68.0, 'OPEN',          'MEDIUM',   '1.0.0', NULL,
     NOW() - INTERVAL '1 hour', NOW()),
    ('b0000000-0000-0000-0000-000000000004', 'c0000000-0000-0000-0000-000000000003',
     'tx:hash:004', 0.4500, 52.0, 'RESOLVED',      'LOW',      '1.0.0', NULL,
     NOW() - INTERVAL '1 day', NOW()),
    ('b0000000-0000-0000-0000-000000000005', 'c0000000-0000-0000-0000-000000000002',
     'tx:hash:005', 0.8800, 91.0, 'OPEN',          'CRITICAL', '1.0.0', NULL,
     NOW() - INTERVAL '30 minutes', NOW())
ON CONFLICT (id) DO NOTHING;

SELECT 'Alerts: ' || count(*) AS status FROM alerts.alerts;
SQL
log_success "Alerts seeded"

log_info "Seeding sample cases..."
psql_run << 'SQL'
INSERT INTO cases.cases
    (id, alert_id, customer_id, status, assigned_to, sar_required, created_at, updated_at) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001',
     'c0000000-0000-0000-0000-000000000001', 'IN_REVIEW',
     'a0000000-0000-0000-0000-000000000003', true,  NOW() - INTERVAL '2 hours', NOW()),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002',
     'c0000000-0000-0000-0000-000000000002', 'OPEN', NULL, false, NOW() - INTERVAL '4 hours', NOW()),
    ('d0000000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000005',
     'c0000000-0000-0000-0000-000000000002', 'PENDING_SAR',
     'a0000000-0000-0000-0000-000000000003', true,  NOW() - INTERVAL '30 minutes', NOW())
ON CONFLICT (id) DO NOTHING;

SELECT 'Cases: ' || count(*) AS status FROM cases.cases;
SQL
log_success "Cases seeded"

log_info "Seeding MongoDB transaction data..."
docker exec fds-mongodb mongosh \
    --username "${MONGO_USER:-mongo_user}" \
    --password "${MONGO_PASSWORD:-changeme_strong_password}" \
    --authenticationDatabase admin \
    "${MONGO_DB:-fraud_detection}" \
    --quiet \
    --eval '
    const col = db.getCollection("transactions");
    const now = new Date();
    const customers = [
        "c0000000-0000-0000-0000-000000000001",
        "c0000000-0000-0000-0000-000000000002",
        "c0000000-0000-0000-0000-000000000003",
        "c0000000-0000-0000-0000-000000000004",
        "c0000000-0000-0000-0000-000000000005"
    ];
    const docs = [];
    for (let i = 0; i < 50; i++) {
        docs.push({
            _id: "tx-seed-" + i,
            customer_id: customers[i % 5],
            tx_hash: "tx:hash:seed:" + i,
            amount: Math.random() * 10000,
            currency: "USD",
            merchant_category: ["retail","gambling","crypto","wire"][i % 4],
            country_code: ["US","GB","NG","RU","CN"][i % 5],
            fraud_probability: Math.random(),
            risk_score: Math.random() * 100,
            timestamp: new Date(now - i * 60000),
            features: { velocity_1h: i % 10, cross_border: i % 3 === 0 }
        });
    }
    const result = col.insertMany(docs, { ordered: false });
    print("Inserted " + result.insertedCount + " transactions");
    ' 2>/dev/null || echo "MongoDB seed skipped (container may not be running or docs already exist)"
log_success "MongoDB data seeded"

echo ""
log_success "All seed data loaded successfully!"
echo "  Test credentials (password for all: ${SEED_PASSWORD}):"
echo "    admin@fraud.local         — ADMIN role"
echo "    analyst@fraud.local       — ANALYST role"
echo "    investigator@fraud.local  — INVESTIGATOR role"
echo "    auditor@fraud.local       — AUDITOR role"
