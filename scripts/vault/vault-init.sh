#!/bin/sh
# =============================================================================
# FRAUD DETECTION SYSTEM — Vault Initialization Script
# Configures Transit secrets engine and initial encryption keys.
# In dev mode Vault starts unsealed — this runs post-startup.
# =============================================================================
set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"

echo "Waiting for Vault to be ready..."
until vault status -address="${VAULT_ADDR}" > /dev/null 2>&1; do
    sleep 2
done

echo "Vault is ready. Configuring..."

# --- Enable Transit secrets engine ---
vault secrets enable -address="${VAULT_ADDR}" \
    -path=transit transit 2>/dev/null || echo "Transit already enabled"

# --- Create PII encryption key (AES-256-GCM) ---
vault write -address="${VAULT_ADDR}" \
    -f transit/keys/fraud-pii-key \
    type=aes256-gcm96

vault write -address="${VAULT_ADDR}" \
    transit/keys/fraud-pii-key/config \
    min_decryption_version=1 \
    deletion_allowed=false \
    auto_rotate_period=2160h  # 90 days

# --- Create document encryption key ---
vault write -address="${VAULT_ADDR}" \
    -f transit/keys/fraud-document-key \
    type=aes256-gcm96

# --- Enable KV v2 for application secrets ---
vault secrets enable -address="${VAULT_ADDR}" \
    -path=secret kv-v2 2>/dev/null || echo "KV already enabled"

# --- Store initial app secrets ---
vault kv put -address="${VAULT_ADDR}" secret/fraud-detection/jwt \
    secret="dev-jwt-secret-min-32-chars-long-123" \
    issuer="fraud-detection-system"

vault kv put -address="${VAULT_ADDR}" secret/fraud-detection/database \
    host="postgres" \
    port="5432" \
    name="fraud_detection" \
    user="fraud_user" \
    password="changeme_strong_password"

# --- Create AppRole for service authentication (production pattern) ---
vault auth enable -address="${VAULT_ADDR}" \
    approle 2>/dev/null || echo "AppRole already enabled"

# Policy for fraud detection services
vault policy write -address="${VAULT_ADDR}" fraud-service - << 'EOF'
# Transit — encrypt/decrypt PII
path "transit/encrypt/fraud-pii-key" {
  capabilities = ["update"]
}
path "transit/decrypt/fraud-pii-key" {
  capabilities = ["update"]
}
path "transit/encrypt/fraud-document-key" {
  capabilities = ["update"]
}
path "transit/decrypt/fraud-document-key" {
  capabilities = ["update"]
}
path "transit/rewrap/fraud-pii-key" {
  capabilities = ["update"]
}
# Key rotation info
path "transit/keys/fraud-pii-key" {
  capabilities = ["read"]
}
# Application secrets
path "secret/data/fraud-detection/*" {
  capabilities = ["read"]
}
path "secret/metadata/fraud-detection/*" {
  capabilities = ["list", "read"]
}
EOF

# Create AppRole for services
vault write -address="${VAULT_ADDR}" \
    auth/approle/role/fraud-service \
    token_policies="fraud-service" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=720h  # 30 days

# Get role-id (for reference)
ROLE_ID=$(vault read -address="${VAULT_ADDR}" \
    -field=role_id auth/approle/role/fraud-service/role-id)
echo "AppRole Role ID: $ROLE_ID"

# Generate a secret-id
SECRET_ID=$(vault write -address="${VAULT_ADDR}" \
    -f -field=secret_id auth/approle/role/fraud-service/secret-id)
echo "AppRole Secret ID: $SECRET_ID"
echo "(Store these in CI/CD secrets — DO NOT commit)"

echo ""
echo "Vault initialization complete."
echo "  Transit key:  transit/keys/fraud-pii-key"
echo "  App secrets:  secret/fraud-detection/*"
echo "  AppRole:      auth/approle/role/fraud-service"
