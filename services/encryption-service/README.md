# Encryption Service

Wraps HashiCorp Vault's Transit secrets engine and exposes a gRPC API for encrypting and decrypting PII. No other service in the system holds encryption keys or performs encryption directly — all cryptographic operations are delegated to this service.

## gRPC port

`50063`

## Required environment variables

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address | `http://localhost:8200` |
| `VAULT_TOKEN` | Static Vault token (for `VAULT_AUTH_METHOD=token`) | — |
| `VAULT_AUTH_METHOD` | `token` or `approle` | `token` |
| `VAULT_APP_ROLE_ID` | AppRole RoleID (for `VAULT_AUTH_METHOD=approle`) | — |
| `VAULT_SECRET_ID` | AppRole SecretID (for `VAULT_AUTH_METHOD=approle`) | — |
| `VAULT_DEFAULT_KEY_NAME` | Transit key name for PII encryption | `fraud-pii-key` |
| `VAULT_KEY_ROTATION_PERIOD` | Auto-rotate period for Transit keys | `2160h` (90 days) |
| `ENCRYPTION_SERVICE_GRPC_PORT` | gRPC listen port | `50063` |
| `SERVICE_NAME` | Service name reported in logs and traces | `encryption-service` |
| `ENVIRONMENT` | `development` / `staging` / `production` | `development` |
| `LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` |
| `JAEGER_ENDPOINT` | Jaeger collector endpoint | `http://localhost:14268/api/traces` |
| `MAX_BATCH_SIZE` | Maximum fields per BatchEncrypt/BatchDecrypt call | `100` |
| `ENCRYPTION_JWT_SECRET` | JWT secret for service-to-service auth (optional) | — |

## Running locally

```bash
# 1. Start Vault in dev mode
vault server -dev -dev-root-token-id=dev-root-token

# 2. Enable the Transit secrets engine
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token
vault secrets enable transit

# 3. Run the service
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=dev-root-token \
go run ./services/encryption-service/cmd/server/
```

## Security notes

- Raw plaintext PII is **never logged** anywhere in this service.
- The Transit key never leaves Vault — only ciphertexts are returned to callers.
- Use AppRole authentication (`VAULT_AUTH_METHOD=approle`) in staging and production.
- Key rotation is handled automatically by Vault according to `VAULT_KEY_ROTATION_PERIOD`.
- Use `RewrapKey` to re-encrypt stored ciphertexts after a key rotation.
