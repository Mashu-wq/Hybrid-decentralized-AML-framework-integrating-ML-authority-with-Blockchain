# Encryption Service

A dedicated microservice that acts as the **single cryptographic gateway** for all Personally Identifiable Information (PII) in the AML Fraud Detection system. Every other service that needs to store or retrieve sensitive customer data must call this service — no service holds encryption keys or performs cryptographic operations directly.

Built on top of **HashiCorp Vault's Transit secrets engine**, which means the encryption key never leaves Vault. The service only ever returns ciphertexts to callers, never raw key material.

---

## Table of Contents

- [Why a Dedicated Encryption Service?](#why-a-dedicated-encryption-service)
- [Architecture Overview](#architecture-overview)
- [Request Flow](#request-flow)
- [Internal Package Structure](#internal-package-structure)
- [gRPC API Reference](#grpc-api-reference)
- [Ciphertext Format](#ciphertext-format)
- [Key Rotation](#key-rotation)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Testing](#testing)
- [Security Model](#security-model)

---

## Why a Dedicated Encryption Service?

In an AML system, customer PII (names, passport numbers, dates of birth, tax IDs) must be:

1. **Encrypted at rest** — a database breach must not expose readable PII.
2. **Auditable** — every encryption and decryption operation must be traceable.
3. **Key-rotation ready** — regulatory compliance often requires periodic key rotation without re-exposing plaintext.
4. **Centrally controlled** — no individual microservice should own or manage encryption keys.

Distributing encryption logic across 10 services would mean 10 places where key management could go wrong. Instead, all cryptographic operations are isolated here, behind a well-defined gRPC contract.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AML Fraud Detection System                   │
│                                                                     │
│   ┌──────────────┐    ┌──────────────┐    ┌─────────────────────┐  │
│   │  KYC Service │    │ Case Service │    │  Analytics Service  │  │
│   │  (Go/gRPC)   │    │  (Go/gRPC)   │    │    (Go/gRPC)        │  │
│   └──────┬───────┘    └──────┬───────┘    └────────┬────────────┘  │
│          │                   │                     │               │
│          │   gRPC calls      │                     │               │
│          └───────────────────┴─────────────────────┘               │
│                              │                                      │
│                              ▼                                      │
│          ┌───────────────────────────────────────┐                  │
│          │         ENCRYPTION SERVICE            │                  │
│          │           localhost:50066             │                  │
│          │                                       │                  │
│          │  ┌─────────────────────────────────┐  │                  │
│          │  │        gRPC Server              │  │                  │
│          │  │  (JWT auth interceptor,         │  │                  │
│          │  │   OpenTelemetry tracing,        │  │                  │
│          │  │   structured logging)           │  │                  │
│          │  └────────────────┬────────────────┘  │                  │
│          │                   │                   │                  │
│          │  ┌────────────────▼────────────────┐  │                  │
│          │  │      EncryptionService          │  │                  │
│          │  │      (business logic)           │  │                  │
│          │  │                                 │  │                  │
│          │  │  • EncryptPII                   │  │                  │
│          │  │  • DecryptPII                   │  │                  │
│          │  │  • BatchEncrypt                 │  │                  │
│          │  │  • BatchDecrypt                 │  │                  │
│          │  │  • RewrapKey                    │  │                  │
│          │  │  • GenerateIdentityHash         │  │                  │
│          │  │  • GetKeyInfo                   │  │                  │
│          │  │  • HealthCheck                  │  │                  │
│          │  └────────────────┬────────────────┘  │                  │
│          │                   │                   │                  │
│          │  ┌────────────────▼────────────────┐  │                  │
│          │  │       VaultClient               │  │                  │
│          │  │  (Transit engine wrapper)       │  │                  │
│          │  └────────────────┬────────────────┘  │                  │
│          └───────────────────┼───────────────────┘                  │
│                              │ HTTPS                                │
│                              ▼                                      │
│          ┌───────────────────────────────────────┐                  │
│          │        HashiCorp Vault                │                  │
│          │          :8200                        │                  │
│          │                                       │                  │
│          │   Transit Secrets Engine              │                  │
│          │   ┌─────────────────────────────┐     │                  │
│          │   │  fraud-pii-key (AES-256-GCM)│     │                  │
│          │   │  v1: [key bytes — NEVER      │     │                  │
│          │   │       leave Vault]           │     │                  │
│          │   └─────────────────────────────┘     │                  │
│          └───────────────────────────────────────┘                  │
│                                                                     │
│                              │ stores only ciphertext               │
│                              ▼                                      │
│          ┌───────────────────────────────────────┐                  │
│          │          PostgreSQL / MongoDB         │                  │
│          │  full_name: "vault:v1:AbCdEfGh..."   │                  │
│          │  dob:       "vault:v1:XyZwVuTs..."   │                  │
│          │  (plaintext PII never stored)        │                  │
│          └───────────────────────────────────────┘                  │
│                                                                     │
│                              │ identity hash only (no PII)         │
│                              ▼                                      │
│          ┌───────────────────────────────────────┐                  │
│          │       Hyperledger Fabric              │                  │
│          │  identity_hash: "a3f9c2d1..."        │                  │
│          │  (SHA-256 of PII — safe on-chain)    │                  │
│          └───────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Request Flow

### Customer Onboarding (Encrypt)

```
Customer submits KYC form
        │
        ▼
┌───────────────┐
│  KYC Service  │  receives: name="John Doe", dob="1990-01-15", passport="AB123456"
└───────┬───────┘
        │
        │  gRPC: BatchEncrypt(fields=[name, dob, passport], key="fraud-pii-key")
        ▼
┌──────────────────────┐
│  Encryption Service  │
└──────────┬───────────┘
           │
           │  Transit Encrypt API call (HTTPS)
           ▼
┌──────────────────────┐
│   HashiCorp Vault    │  AES-256-GCM encryption happens here
│  (Transit Engine)    │  Key material never leaves Vault
└──────────┬───────────┘
           │
           │  returns: "vault:v1:AbCdEf...", "vault:v1:XyZwVu...", "vault:v1:PqRsT..."
           ▼
┌──────────────────────┐
│  Encryption Service  │  passes ciphertexts back
└──────────┬───────────┘
           │
           ▼
┌───────────────┐
│  KYC Service  │  stores ciphertexts in PostgreSQL
└───────┬───────┘
        │
        │  gRPC: GenerateIdentityHash(name, dob, passport, country)
        ▼
┌──────────────────────┐
│  Encryption Service  │  SHA-256("john doe|1990-01-15|passport|AB123456|US")
└──────────┬───────────┘
           │  returns: "a3f9c2d1e4b8..." (safe to publish)
           ▼
┌───────────────┐
│  KYC Service  │  anchors identity_hash on Hyperledger Fabric
└───────────────┘
```

### Analyst Views Customer PII (Decrypt)

```
Analyst requests customer record
        │
        ▼
┌───────────────┐
│  KYC Service  │  fetches ciphertexts from PostgreSQL
└───────┬───────┘
        │
        │  gRPC: BatchDecrypt(fields=["vault:v1:AbCdEf...", ...])
        ▼
┌──────────────────────┐
│  Encryption Service  │
└──────────┬───────────┘
           │
           │  Transit Decrypt API call
           ▼
┌──────────────────────┐
│   HashiCorp Vault    │  decrypts using stored key version
└──────────┬───────────┘
           │  returns: plaintext bytes (NEVER logged)
           ▼
┌──────────────────────┐
│  Encryption Service  │
└──────────┬───────────┘
           │
           ▼
┌───────────────┐
│  KYC Service  │  returns plaintext to authorized analyst only
└───────────────┘
```

---

## Internal Package Structure

```
services/encryption-service/
│
├── cmd/server/
│   └── main.go                  # Entry point: wires config → vault → service → gRPC server
│
├── internal/
│   ├── config/
│   │   └── config.go            # Loads all config from env vars with defaults
│   │
│   ├── vault/
│   │   └── client.go            # VaultClient: wraps Transit engine (Encrypt, Decrypt,
│   │                            #   Rewrap, GetKeyMetadata, EnsureKeyExists, Ping)
│   │
│   ├── service/
│   │   ├── encryption_service.go  # Business logic: validates input, calls VaultOperations
│   │   └── encryption_service_test.go  # Unit tests with mock VaultOperations
│   │
│   └── grpc/
│       └── server.go            # Registers gRPC server, JWT interceptor, OTel tracing
│
└── README.md
```

### Layer Responsibilities

| Layer | File | Responsibility |
|---|---|---|
| **Entry point** | `cmd/server/main.go` | Load config, connect Vault, wire dependencies, handle SIGTERM |
| **gRPC server** | `internal/grpc/server.go` | JWT auth interceptor, OpenTelemetry tracing, register handler |
| **Service** | `internal/service/encryption_service.go` | Input validation, orchestrate Vault calls, error mapping to gRPC codes |
| **Vault client** | `internal/vault/client.go` | Base64 encode/decode, call Vault REST API, parse ciphertext format |

The service layer depends only on the `VaultOperations` **interface**, not the concrete `VaultClient`. This makes it fully unit-testable with mocks without a running Vault.

---

## gRPC API Reference

Proto source: [`proto/encryption.proto`](../../proto/encryption.proto)

### EncryptPII

Encrypts a single plaintext value using the Transit key.

**Request**
```json
{
  "meta": {
    "request_id": "uuid-v4",
    "caller_svc": "kyc-service"
  },
  "key_name": "fraud-pii-key",
  "plaintext": "<base64-encoded bytes>",
  "context": "customer-id-123"
}
```

**Response**
```json
{
  "ciphertext": "vault:v1:AbCdEfGhIjKl...",
  "key_version": 1
}
```

> `context` is optional. When provided, the ciphertext is cryptographically bound to that string — decryption will fail unless the same context is supplied. Use a stable customer ID to prevent cross-customer decryption.

---

### DecryptPII

Decrypts a Vault ciphertext back to plaintext. Only call when PII must be displayed to an authorized user.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "kyc-service" },
  "key_name": "fraud-pii-key",
  "ciphertext": "vault:v1:AbCdEfGhIjKl...",
  "context": "customer-id-123"
}
```

**Response**
```json
{
  "plaintext": "<base64-encoded bytes>"
}
```

---

### BatchEncrypt

Encrypts multiple named PII fields in a single round-trip. Used during customer onboarding to encrypt all fields (name, DOB, document number, tax ID) atomically.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "kyc-service" },
  "key_name": "fraud-pii-key",
  "fields": [
    { "field_name": "full_name",       "plaintext": "Sm9obiBEb2U=" },
    { "field_name": "date_of_birth",   "plaintext": "MTk5MC0wMS0xNQ==" },
    { "field_name": "passport_number", "plaintext": "QUIxMjM0NTY=" }
  ]
}
```

**Response**
```json
{
  "fields": [
    { "field_name": "full_name",       "ciphertext": "vault:v1:Abc...", "key_version": 1 },
    { "field_name": "date_of_birth",   "ciphertext": "vault:v1:Def...", "key_version": 1 },
    { "field_name": "passport_number", "ciphertext": "vault:v1:Ghi...", "key_version": 1 }
  ]
}
```

> Maximum 100 fields per batch (configurable via `MAX_BATCH_SIZE`).

---

### BatchDecrypt

Decrypts multiple named fields in one round-trip.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "kyc-service" },
  "key_name": "fraud-pii-key",
  "fields": [
    { "field_name": "full_name",     "ciphertext": "vault:v1:Abc..." },
    { "field_name": "date_of_birth", "ciphertext": "vault:v1:Def..." }
  ]
}
```

**Response**
```json
{
  "fields": [
    { "field_name": "full_name",     "plaintext": "Sm9obiBEb2U=" },
    { "field_name": "date_of_birth", "plaintext": "MTk5MC0wMS0xNQ==" }
  ]
}
```

---

### GenerateIdentityHash

Generates a deterministic SHA-256 hash of PII fields. The hash is safe to store in plaintext on the blockchain because it cannot be reversed to recover the original PII.

Used to give Hyperledger Fabric a stable customer reference without ever putting real PII on-chain.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "kyc-service" },
  "full_name":       "John Doe",
  "date_of_birth":   "1990-01-15",
  "document_number": "AB123456",
  "document_type":   "PASSPORT",
  "country_code":    "US"
}
```

**Response**
```json
{
  "identity_hash": "a3f9c2d1e4b87f6c2a1d9e5b3c7f0a4d2e8b1c6d5f3a9b7e4c2d0f1a8b5c3e",
  "algorithm": "SHA-256"
}
```

> Inputs are normalised before hashing: `full_name` and `document_type` are lowercased, whitespace is trimmed, `country_code` is uppercased. This ensures `"JOHN DOE"` and `"john doe"` produce the same hash.

---

### RewrapKey

Re-encrypts existing ciphertexts under the latest key version. The plaintext **never leaves Vault** during this operation — Vault decrypts and re-encrypts internally.

Call this after a key rotation to migrate stored ciphertexts to the new key version.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "case-service" },
  "key_name": "fraud-pii-key",
  "ciphertexts": [
    "vault:v1:AbCdEf...",
    "vault:v1:GhIjKl..."
  ]
}
```

**Response**
```json
{
  "new_ciphertexts": [
    "vault:v2:MnOpQr...",
    "vault:v2:StUvWx..."
  ],
  "new_key_version": 2
}
```

---

### GetKeyInfo

Returns current key version, minimum decryptable version, and rotation schedule.

**Request**
```json
{
  "meta": { "request_id": "uuid-v4", "caller_svc": "admin-tool" },
  "key_name": "fraud-pii-key"
}
```

**Response**
```json
{
  "key_name":            "fraud-pii-key",
  "current_version":     2,
  "min_decrypt_version": 1,
  "rotation_period":     "2160h",
  "deletion_allowed":    false
}
```

---

### HealthCheck

Checks whether the service can reach Vault. Used by Docker health checks and the API Gateway's liveness probe.

**Request**
```json
{ "service": "encryption-service" }
```

**Response (healthy)**
```json
{ "status": "HEALTH_STATUS_SERVING", "details": "vault reachable" }
```

**Response (Vault down)**
```json
{ "status": "HEALTH_STATUS_NOT_SERVING", "details": "vault health check: connection refused" }
```

---

## Ciphertext Format

All ciphertexts produced by Vault Transit follow this format:

```
vault:v{N}:{base64-encoded-ciphertext}
  │     │    │
  │     │    └── AES-256-GCM encrypted + authenticated bytes, base64-encoded
  │     └─────── key version number (increments on each rotation)
  └───────────── literal prefix — the service validates this on every DecryptPII call
```

Example: `vault:v1:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789==`

Storing the key version inside the ciphertext means:
- You always know which key version was used to encrypt a record.
- After rotation, old ciphertexts (`v1`) can still be decrypted as long as `min_decryption_version` allows it.
- `RewrapKey` migrates `v1` → `v2` ciphertexts without exposing plaintext.

---

## Key Rotation

Key rotation is a zero-downtime operation:

```
Step 1: Vault rotates the key (automatic every 90 days, or triggered manually)
        fraud-pii-key: v1 → v2

Step 2: New encryptions use v2 automatically
        New records: "vault:v2:..."

Step 3: Old records still have "vault:v1:..." ciphertexts
        Decryption still works because min_decryption_version = 1

Step 4: Run RewrapKey job to migrate old records
        "vault:v1:..." → "vault:v2:..." (plaintext never exposed)

Step 5: Once all records are on v2, raise min_decryption_version to 2
        v1 ciphertexts can no longer be decrypted (defense in depth)
```

To rotate manually:
```bash
# Trigger rotation
curl -X POST http://localhost:8200/v1/transit/keys/fraud-pii-key/rotate \
  -H "X-Vault-Token: $VAULT_TOKEN"

# Verify new version
curl http://localhost:8200/v1/transit/keys/fraud-pii-key \
  -H "X-Vault-Token: $VAULT_TOKEN" | jq '.data.latest_version'

# Then call RewrapKey RPC to migrate stored ciphertexts
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address | `http://localhost:8200` |
| `VAULT_TOKEN` | Static Vault token (`token` auth method) | **required** |
| `VAULT_AUTH_METHOD` | `token` or `approle` | `token` |
| `VAULT_APP_ROLE_ID` | AppRole RoleID (`approle` auth method) | — |
| `VAULT_SECRET_ID` | AppRole SecretID (`approle` auth method) | — |
| `VAULT_DEFAULT_KEY_NAME` | Transit key name used when `key_name` is empty | `fraud-pii-key` |
| `VAULT_KEY_ROTATION_PERIOD` | Auto-rotation period for the Transit key | `2160h` (90 days) |
| `ENCRYPTION_SERVICE_GRPC_PORT` | gRPC listen port | `50066` |
| `ENCRYPTION_JWT_SECRET` | JWT HMAC secret for service-to-service auth (empty = no auth) | — |
| `SERVICE_NAME` | Service name in logs and traces | `encryption-service` |
| `ENVIRONMENT` | `development` / `staging` / `production` | `development` |
| `LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` |
| `JAEGER_ENDPOINT` | OpenTelemetry/Jaeger collector endpoint | `http://localhost:14268/api/traces` |
| `MAX_BATCH_SIZE` | Maximum fields per BatchEncrypt / BatchDecrypt call | `100` |

---

## Running Locally

### Option 1 — Docker Compose (recommended)

```bash
# From project root — starts Vault + all services
make infra-up
make run

# Verify the service is healthy
grpcurl -plaintext \
  -import-path proto \
  -proto common.proto \
  -proto encryption.proto \
  -d '{"service":"encryption-service"}' \
  localhost:50066 \
  fraud.encryption.v1.EncryptionService/HealthCheck
```

### Option 2 — Run standalone

```bash
# 1. Start Vault (already running if infra-up was used)
#    Or start a local dev instance:
vault server -dev -dev-root-token-id=dev-root-token &

# 2. Enable Transit engine and create the key
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault secrets enable transit
vault write -f transit/keys/fraud-pii-key type=aes256-gcm96

# 3. Run the service from project root
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=dev-root-token \
ENCRYPTION_SERVICE_GRPC_PORT=50066 \
go run ./services/encryption-service/cmd/server/
```

### Quick smoke test with grpcurl

Run all commands from the **project root** directory.

```bash
# Health check
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{"service":"encryption-service"}' \
  localhost:50066 fraud.encryption.v1.EncryptionService/HealthCheck

# Encrypt a value  ("Hello World" base64 = SGVsbG8gV29ybGQ=)
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{
    "meta": {"request_id":"test-1","caller_svc":"terminal"},
    "key_name": "fraud-pii-key",
    "plaintext": "SGVsbG8gV29ybGQ="
  }' \
  localhost:50066 fraud.encryption.v1.EncryptionService/EncryptPII

# Decrypt — paste the ciphertext from the previous response
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{
    "meta": {"request_id":"test-2","caller_svc":"terminal"},
    "key_name": "fraud-pii-key",
    "ciphertext": "vault:v1:<paste here>"
  }' \
  localhost:50066 fraud.encryption.v1.EncryptionService/DecryptPII

# Generate identity hash (safe to store on blockchain)
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{
    "meta": {"request_id":"test-3","caller_svc":"terminal"},
    "full_name": "John Doe",
    "date_of_birth": "1990-01-15",
    "document_number": "AB123456",
    "document_type": "PASSPORT",
    "country_code": "US"
  }' \
  localhost:50066 fraud.encryption.v1.EncryptionService/GenerateIdentityHash

# Batch encrypt multiple PII fields at once
# "John Doe" = Sm9obiBEb2U=   "1990-01-15" = MTk5MC0wMS0xNQ==
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{
    "meta": {"request_id":"test-4","caller_svc":"terminal"},
    "key_name": "fraud-pii-key",
    "fields": [
      {"field_name":"full_name",     "plaintext":"Sm9obiBEb2U="},
      {"field_name":"date_of_birth", "plaintext":"MTk5MC0wMS0xNQ=="}
    ]
  }' \
  localhost:50066 fraud.encryption.v1.EncryptionService/BatchEncrypt

# Get key metadata
grpcurl -plaintext \
  -import-path proto -proto common.proto -proto encryption.proto \
  -d '{
    "meta": {"request_id":"test-5","caller_svc":"terminal"},
    "key_name": "fraud-pii-key"
  }' \
  localhost:50066 fraud.encryption.v1.EncryptionService/GetKeyInfo
```

---

## Testing

### Unit tests (no Vault required)

The service layer is tested with a mock `VaultOperations` interface so tests run instantly without any infrastructure.

```bash
cd services/encryption-service
go test -v -race ./internal/service/...
```

Test coverage includes:
- `EncryptPII` — success, empty plaintext, Vault error, default key fallback
- `DecryptPII` — success, invalid ciphertext format (`not-a-vault:...`), Vault error
- `BatchEncrypt` — success with multiple fields, batch size exceeded
- `GenerateIdentityHash` — determinism (same input → same hash), normalisation (case/whitespace insensitive), different inputs produce different hashes, missing fields return `InvalidArgument`
- `HealthCheck` — Vault up returns `SERVING`, Vault down returns `NOT_SERVING`

### Run all Go tests for the service

```bash
cd services/encryption-service && go test -v -race ./...
```

### Run from project root

```bash
make test-unit-go
```

---

## Security Model

### What is protected

| Data | Protection |
|---|---|
| Customer name, DOB, document numbers | AES-256-GCM encrypted via Vault Transit before any DB write |
| Encryption key bytes | Never leave Vault — only ciphertexts cross the network |
| Plaintext in logs | Explicitly blocked — all methods have `// DO NOT LOG` guards |
| Blockchain records | Only `identity_hash` (SHA-256) stored — PII never on-chain |

### Authentication

- **Development**: `ENCRYPTION_JWT_SECRET` is unset → no JWT validation. All calls are accepted (internal network only).
- **Production**: Set `ENCRYPTION_JWT_SECRET` to require a valid HMAC-SHA256 bearer token on all RPCs except `HealthCheck`. Only internal services with a signed token can call decrypt.

### Vault authentication

| Method | When to use |
|---|---|
| `VAULT_AUTH_METHOD=token` | Local development only. Static tokens are a security risk in production. |
| `VAULT_AUTH_METHOD=approle` | Staging and production. Short-lived, revocable tokens. Set `VAULT_APP_ROLE_ID` and `VAULT_SECRET_ID`. |

### Threat model

| Threat | Mitigation |
|---|---|
| Database breach | Attacker gets only `vault:v1:...` ciphertexts — useless without Vault access |
| Log scraping | Plaintext is explicitly never logged anywhere in this service |
| Key compromise | Vault key rotation + RewrapKey migrates all records to new key; old key version can be retired |
| Cross-customer decryption | `context` field binds ciphertext to a customer ID — decryption fails with wrong context |
| Service impersonation | JWT bearer token required in production; only trusted internal services have a valid token |
