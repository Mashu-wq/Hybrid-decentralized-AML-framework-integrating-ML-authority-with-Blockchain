#!/usr/bin/env bash
# =============================================================================
# FRAUD DETECTION SYSTEM — Seed Development Data
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[SEED]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }

# --- Load env ---
if [ -f ".env" ]; then source .env; fi

PGCONN="postgresql://${POSTGRES_USER:-fraud_user}:${POSTGRES_PASSWORD:-changeme_strong_password}@${POSTGRES_HOST:-localhost}:${POSTGRES_PORT:-5432}/${POSTGRES_DB:-fraud_detection}"

log_info "Seeding IAM roles and admin user..."
psql "$PGCONN" << 'SQL'
-- Seed roles
INSERT INTO roles (id, name, description, created_at) VALUES
    ('role-admin',        'ADMIN',       'Full system access',                         NOW()),
    ('role-analyst',      'ANALYST',     'View and triage fraud alerts',               NOW()),
    ('role-investigator', 'INVESTIGATOR','Manage cases, attach evidence',              NOW()),
    ('role-auditor',      'AUDITOR',     'Read-only audit trail access',               NOW()),
    ('role-api-client',   'API_CLIENT',  'Machine-to-machine API access',              NOW())
ON CONFLICT (id) DO NOTHING;

-- Seed admin user (password: Admin@12345 — bcrypt cost 12)
INSERT INTO users (id, email, password_hash, role_id, mfa_enabled, active, created_at) VALUES
    ('user-admin-001', 'admin@fraud.local',
     '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lfk0kl3Q5PdFmh9Oy',
     'role-admin', false, true, NOW())
ON CONFLICT (email) DO NOTHING;

-- Seed test analyst
INSERT INTO users (id, email, password_hash, role_id, mfa_enabled, active, created_at) VALUES
    ('user-analyst-001', 'analyst@fraud.local',
     '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lfk0kl3Q5PdFmh9Oy',
     'role-analyst', false, true, NOW())
ON CONFLICT (email) DO NOTHING;

-- Seed test investigator
INSERT INTO users (id, email, password_hash, role_id, mfa_enabled, active, created_at) VALUES
    ('user-inv-001', 'investigator@fraud.local',
     '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lfk0kl3Q5PdFmh9Oy',
     'role-investigator', false, true, NOW())
ON CONFLICT (email) DO NOTHING;

SELECT 'IAM seed complete' as status;
SQL
log_success "IAM data seeded"

log_info "Seeding KYC test customers..."
psql "$PGCONN" << 'SQL'
-- Seed KYC records (PII fields would be encrypted in real service)
INSERT INTO kyc_records (id, identity_hash, kyc_status, risk_level, verifier_id, created_at, updated_at) VALUES
    ('kyc-001', 'sha256:aabbcc001', 'APPROVED',  'LOW',      'user-analyst-001', NOW(), NOW()),
    ('kyc-002', 'sha256:aabbcc002', 'APPROVED',  'MEDIUM',   'user-analyst-001', NOW(), NOW()),
    ('kyc-003', 'sha256:aabbcc003', 'PENDING',   'HIGH',     NULL,               NOW(), NOW()),
    ('kyc-004', 'sha256:aabbcc004', 'REJECTED',  'HIGH',     'user-analyst-001', NOW(), NOW()),
    ('kyc-005', 'sha256:aabbcc005', 'APPROVED',  'LOW',      'user-analyst-001', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

SELECT 'KYC seed complete' as status;
SQL
log_success "KYC data seeded"

log_info "Seeding sample alerts..."
psql "$PGCONN" << 'SQL'
INSERT INTO alerts (id, customer_id, tx_hash, fraud_probability, risk_score, status, priority, model_version, created_at, updated_at) VALUES
    ('alert-001', 'kyc-001', 'tx:hash:001', 0.92, 95.0, 'OPEN',          'CRITICAL', 'v1.0', NOW() - INTERVAL '2 hours', NOW()),
    ('alert-002', 'kyc-002', 'tx:hash:002', 0.78, 82.0, 'INVESTIGATING', 'HIGH',     'v1.0', NOW() - INTERVAL '4 hours', NOW()),
    ('alert-003', 'kyc-001', 'tx:hash:003', 0.61, 68.0, 'OPEN',          'MEDIUM',   'v1.0', NOW() - INTERVAL '1 hour',  NOW()),
    ('alert-004', 'kyc-003', 'tx:hash:004', 0.45, 52.0, 'RESOLVED',      'LOW',      'v1.0', NOW() - INTERVAL '1 day',   NOW()),
    ('alert-005', 'kyc-002', 'tx:hash:005', 0.88, 91.0, 'OPEN',          'CRITICAL', 'v1.0', NOW() - INTERVAL '30 min',  NOW())
ON CONFLICT (id) DO NOTHING;

SELECT 'Alert seed complete' as status;
SQL
log_success "Alert data seeded"

log_info "Seeding sample cases..."
psql "$PGCONN" << 'SQL'
INSERT INTO cases (id, alert_id, customer_id, status, assigned_to, created_at, updated_at) VALUES
    ('case-001', 'alert-001', 'kyc-001', 'IN_REVIEW',    'user-inv-001', NOW() - INTERVAL '2 hours', NOW()),
    ('case-002', 'alert-002', 'kyc-002', 'OPEN',         NULL,          NOW() - INTERVAL '4 hours', NOW()),
    ('case-003', 'alert-005', 'kyc-002', 'PENDING_SAR',  'user-inv-001', NOW() - INTERVAL '30 min',  NOW())
ON CONFLICT (id) DO NOTHING;

SELECT 'Case seed complete' as status;
SQL
log_success "Case data seeded"

log_info "Seeding MongoDB transaction data..."
# Use mongosh to seed time-series transaction documents
docker exec fds-mongodb mongosh \
    --username "${MONGO_USER:-mongo_user}" \
    --password "${MONGO_PASSWORD:-changeme_strong_password}" \
    --authenticationDatabase admin \
    "${MONGO_DB:-fraud_detection}" \
    --eval '
    const col = db.getCollection("transactions");
    const now = new Date();
    const docs = [];
    for (let i = 0; i < 50; i++) {
        docs.push({
            _id: "tx-seed-" + i,
            customer_id: "kyc-00" + ((i % 5) + 1),
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
    ' 2>/dev/null || echo "MongoDB seed skipped (container may not be running)"
log_success "MongoDB data seeded"

echo ""
log_success "All seed data loaded successfully!"
echo "  Test credentials (password for all: Admin@12345):"
echo "    admin@fraud.local        — ADMIN role"
echo "    analyst@fraud.local      — ANALYST role"
echo "    investigator@fraud.local — INVESTIGATOR role"
