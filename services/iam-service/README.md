# IAM Service — Identity & Access Management

The IAM service is the **security backbone** of the Blockchain-Based KYC/AML Fraud Detection System. It is responsible for every aspect of identity and access: who can enter the system, what they are allowed to do, and a tamper-evident log of every security event that occurs.

Every inbound request to any service in the system is validated through IAM first. No other service issues or accepts tokens — IAM is the single source of truth for authentication and authorization.

---

## Table of Contents

1. [Role in the System](#1-role-in-the-system)
2. [Architecture](#2-architecture)
3. [Internal Layer Breakdown](#3-internal-layer-breakdown)
4. [API Reference](#4-api-reference)
5. [Security Mechanisms](#5-security-mechanisms)
6. [RBAC: Roles and Permissions](#6-rbac-roles-and-permissions)
7. [Data Storage](#7-data-storage)
8. [Configuration](#8-configuration)
9. [Running the Service](#9-running-the-service)
10. [Testing with Postman](#10-testing-with-postman)
11. [Testing with grpcurl](#11-testing-with-grpcurl)
12. [Error Codes](#12-error-codes)
13. [Audit Events](#13-audit-events)

---

## 1. Role in the System

```
                    ┌──────────────────────────────────────────┐
                    │             External Clients              │
                    │   (Browser / Mobile App / API Consumer)  │
                    └─────────────────┬────────────────────────┘
                                      │ HTTPS
                                      ▼
                    ┌──────────────────────────────────────────┐
                    │              API Gateway                  │
                    │  • Validates JWT by calling IAM           │
                    │  • Caches result by SHA-256(token)        │
                    │  • Injects RequestMetadata into headers   │
                    └──────┬──────────────────────┬────────────┘
                           │ gRPC ValidateToken    │ gRPC (other methods)
                           ▼                       ▼
          ┌────────────────────────┐    ┌──────────────────────┐
          │      IAM Service       │    │   Other Services      │
          │  • Authentication      │    │  alert-service        │
          │  • JWT issuance        │    │  kyc-service          │
          │  • Token validation    │    │  case-service         │
          │  • RBAC permissions    │    │  transaction-service  │
          │  • MFA (TOTP)          │    │  analytics-service    │
          │  • Audit logging       │    │  (trust JWT claims,   │
          └────────────────────────┘    │   no second IAM call) │
                                        └──────────────────────┘
```

The API Gateway calls `ValidateToken` once per inbound request. The resulting `user_id`, `role`, and `permissions` are embedded in gRPC metadata headers (`RequestMetadata`) and forwarded to downstream services. Downstream services read these values directly — they do **not** call IAM again on every operation, keeping latency low.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         IAM Service                              │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    gRPC Layer  (:50060)                   │    │
│  │                                                           │    │
│  │   server.go  — registers interceptors, health, reflection │    │
│  │   handler.go — translates proto ↔ domain types           │    │
│  │                                                           │    │
│  │   Interceptors (from shared/middleware):                  │    │
│  │     • Auth    — validates JWT on protected methods        │    │
│  │     • Logging — structured request/response logging       │    │
│  │     • Tracing — OpenTelemetry span propagation            │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │                    Service Layer                          │    │
│  │                                                           │    │
│  │   auth_service.go  — all authentication & user mgmt      │    │
│  │   token_service.go — JWT lifecycle + refresh tokens       │    │
│  │   mfa_service.go   — TOTP generation & verification       │    │
│  └────────────┬──────────────────────┬───────────────────────┘   │
│               │                      │                            │
│  ┌────────────▼──────────┐  ┌────────▼──────────────────────┐   │
│  │   PostgreSQL Repo     │  │       Redis Repo               │   │
│  │                       │  │                                │   │
│  │  user_repo.go         │  │  token_repo.go                 │   │
│  │  • User CRUD          │  │  • JTI blocklist               │   │
│  │  • Refresh tokens     │  │  • Session tracking            │   │
│  │  • Permissions        │  │  • Rate limit counters         │   │
│  │  • Audit log          │  │  • MFA challenges              │   │
│  └────────────┬──────────┘  └────────┬───────────────────────┘   │
│               │                      │                            │
└───────────────┼──────────────────────┼────────────────────────────┘
                │                      │
     ┌──────────▼───────┐   ┌──────────▼──────────┐
     │  PostgreSQL 15   │   │     Redis 7          │
     │  iam schema      │   │  • jti:<uuid>        │
     │  • users         │   │  • session:<userID>  │
     │  • roles         │   │  • ratelimit:login:* │
     │  • permissions   │   │  • mfa_challenge:*   │
     │  • role_perms    │   └─────────────────────┘
     │  • refresh_tokens│
     │  • audit_log     │
     └──────────────────┘
```

---

## 3. Internal Layer Breakdown

### `cmd/server/main.go` — Entry Point

Loads configuration, establishes database connections, wires all dependencies together (repositories → services → gRPC server), and blocks until SIGTERM/SIGINT is received. On shutdown, performs a graceful gRPC stop within a 5-second timeout.

Startup order:
1. Load config from environment variables
2. Init structured logger (zerolog)
3. Init OpenTelemetry tracer → Jaeger
4. Connect to PostgreSQL (pgxpool, 15s timeout, ping)
5. Connect to Redis (ping)
6. Build repositories (`UserRepo`, `TokenRepo`)
7. Build services (`TokenService`, `MFAService`, `AuthService`)
8. Start gRPC server on `:50060`
9. Wait for SIGTERM/SIGINT

### `internal/config/config.go` — Configuration

Reads all settings from environment variables with type-safe helpers. Two variables are **required** — the service refuses to start if they are missing:
- `POSTGRES_PASSWORD`
- `JWT_SECRET` (minimum 32 characters)

All other variables have sensible defaults for local development.

### `internal/domain/user.go` — Domain Models

Pure Go structs with no database or transport dependencies. Contains:
- `User` — the core identity entity
- `RefreshToken` — device-bound session token
- `TokenClaims` — validated JWT payload
- `Permission` — `resource:action` pair
- `AuditEvent` — security event record
- `Role` constants and `IsValid()` guard
- `AuthError` — structured error with machine-readable code
- All `ErrCode` constants (e.g. `INVALID_CREDENTIALS`, `TOKEN_EXPIRED`)

### `internal/service/auth_service.go` — Business Logic

The core of the service. Has no knowledge of gRPC, HTTP, PostgreSQL, or Redis — it depends only on interfaces (`UserRepository`, `RateLimiter`, `MFAChallengeStore`). This makes it fully unit-testable without any infrastructure.

Key methods:

| Method | What it does |
|---|---|
| `Register` | Validates email/password, bcrypt-hashes, creates user |
| `Login` | Rate limit → fetch user → bcrypt verify → MFA → issue tokens |
| `VerifyMFA` | Resolves pending MFA challenge → issues tokens |
| `RefreshTokens` | Validates + rotates refresh token → issues new access token |
| `Logout` | Blocks JTI in Redis; optionally revokes all sessions |
| `ChangePassword` | Verifies current password → updates bcrypt hash |
| `SetupMFA` | Generates TOTP secret + 8 backup codes → stores hashed codes |
| `ValidateToken` | Delegates to `TokenService` (signature + JTI check) |
| `GetPermissions` | Fetches role permissions from DB |
| `UpdateUser` | Admin: change role or active status |
| `DeactivateUser` | Marks inactive + revokes all sessions and tokens |

### `internal/service/token_service.go` — JWT Lifecycle

Handles all JWT operations:
- **`IssueAccessToken`** — creates HS256 JWT with `uid`, `email`, `role`, `perms` claims. Stores JTI in Redis session tracker.
- **`ValidateAccessToken`** — parses JWT, checks signature, expiry, issuer, and JTI blocklist (O(1) Redis lookup).
- **`IssueRefreshToken`** — generates 48 random bytes (384-bit entropy), returns raw token (to client) and SHA-256 hash (stored in DB). Raw token is never stored.
- **`RevokeAccessToken`** — adds JTI to Redis blocklist for the token's remaining TTL.
- **`RevokeAllUserSessions`** — invalidates all active JTIs for a user (used on logout-all and deactivation).

### `internal/service/mfa_service.go` — TOTP & Backup Codes

- **`GenerateSecret`** — uses `pquerna/otp` to create a TOTP secret and `otpauth://` URL for QR code display.
- **`Verify`** — validates a 6-digit TOTP code with ±1 step (30-second window) tolerance.
- **`GenerateBackupCodes`** — generates N random codes in `XXXXX-XXXXX` format, bcrypt-hashes each one. Returns both raw (shown to user once) and hashed (stored in DB).
- **`VerifyBackupCode`** — runs bcrypt compare against all stored hashes. Checks all entries even after a match (timing-attack resistant via `subtle.ConstantTimeSelect`).

### `internal/grpc/handler.go` — gRPC Handler

Translates proto request/response types to/from domain types and calls the service layer. Also responsible for:
- Extracting the `authorization` header from incoming gRPC metadata for the `Logout` endpoint
- Mapping `domain.AuthError` codes to appropriate `google.golang.org/grpc/codes` (e.g. `ErrAccountLocked` → `codes.PermissionDenied`)
- Converting `time.Time` to `timestamppb.Timestamp` for proto responses

### `internal/grpc/server.go` — gRPC Server

Wires up the gRPC server with the full interceptor chain:
- **Auth interceptor** — validates JWT on all methods except the `publicMethods` list
- **Logging interceptor** — logs method, duration, status code, trace/span IDs
- **Tracing interceptor** — creates OpenTelemetry spans, propagates trace context

Registers three gRPC services:
- `fraud.iam.v1.IAMService` — the main service
- `grpc.health.v1.Health` — standard Kubernetes/Docker health protocol
- gRPC server reflection — allows tools like Postman and grpcurl to discover methods

### `internal/repository/postgres/user_repo.go` — PostgreSQL Adapter

Implements `service.UserRepository` using `pgx/v5`. Uses parameterized queries throughout (no string interpolation — prevents SQL injection). Connection pooling via `pgxpool` with configurable min/max connections.

### `internal/repository/redis/token_repo.go` — Redis Adapter

Implements `service.TokenRepository` and `service.RateLimiter`. Uses Redis pipelining for the rate limiter (`INCR` + `EXPIRENZ` in one round trip). Key prefixes prevent collisions between different data types.

---

## 4. API Reference

All methods communicate over **gRPC** on port `50060`. The proto package is `fraud.iam.v1`, service name `IAMService`.

### Public Methods (no JWT required)

---

#### `Register`

Creates a new user account. The default assigned role is `ANALYST`. Only an authenticated `ADMIN` caller can assign any other role.

**Request**
```json
{
  "email": "analyst@company.com",
  "password": "MySecure@Pass123",
  "role": "ANALYST"
}
```

**Response**
```json
{
  "userId": "a1b2c3d4-...",
  "email": "analyst@company.com",
  "role": "ANALYST",
  "createdAt": "2026-05-27T14:00:00Z"
}
```

**Password policy:** minimum 12 characters; must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.

---

#### `Login`

Authenticates a user and issues tokens. If MFA is enabled on the account and no `mfa_code` is provided, the response returns `mfa_required: true` and a `mfa_challenge_id` — the client must then call `MFAVerify` to complete login.

**Request**
```json
{
  "email": "analyst@company.com",
  "password": "MySecure@Pass123",
  "mfa_code": "",
  "device_id": "browser-chrome-mac-01",
  "ip_address": "192.168.1.10",
  "user_agent": "Mozilla/5.0 ..."
}
```

**Response (MFA not enabled)**
```json
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "a3f9b2...",
  "accessExpiresIn": "900",
  "refreshExpiresIn": "604800",
  "tokenType": "Bearer",
  "mfaRequired": false,
  "user": {
    "id": "a1b2c3d4-...",
    "email": "analyst@company.com",
    "role": "ANALYST",
    "mfaEnabled": false,
    "active": true
  }
}
```

**Response (MFA required)**
```json
{
  "mfaRequired": true,
  "mfaChallengeId": "challenge-uuid-...",
  "accessToken": "",
  "refreshToken": ""
}
```

---

#### `MFAVerify`

Completes a pending MFA challenge. Accepts either a live TOTP code from an authenticator app or a one-time backup code. A used backup code is permanently removed.

**Request**
```json
{
  "mfa_challenge_id": "challenge-uuid-...",
  "totp_code": "482910"
}
```

**Response**
```json
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "a3f9b2...",
  "accessExpiresIn": "900",
  "mfaEnabled": true
}
```

---

#### `RefreshToken`

Exchanges a valid refresh token for a new access token. The submitted refresh token is revoked and replaced with a new one (token rotation). Device binding is enforced — if `device_id` does not match the one used at login, the token is immediately revoked and a `TOKEN_INVALID` error is returned.

**Request**
```json
{
  "refresh_token": "a3f9b2...",
  "device_id": "browser-chrome-mac-01"
}
```

**Response**
```json
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "newtoken...",
  "accessExpiresIn": "900"
}
```

---

#### `MFASetup`

Generates a new TOTP secret and backup codes for a user. The `secret` and `backup_codes` fields in the response are shown **once only** — they must not be re-requested and the raw values are never stored by the server.

**Request** *(requires valid JWT in metadata)*
```json
{
  "user_id": "a1b2c3d4-..."
}
```

**Response**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCodeUrl": "otpauth://totp/FraudDetectionSystem:analyst@company.com?secret=...",
  "backupCodes": [
    "a3f9b-2c8d1",
    "e7f01-9a2b4",
    "..."
  ]
}
```

---

### Authenticated Methods (JWT required in `authorization` metadata)

---

#### `Logout`

Revokes the current access token by blocklisting its JTI in Redis. If `all_devices` is `true`, all refresh tokens in PostgreSQL and all session JTIs in Redis are also revoked.

**Metadata header required:** `authorization: Bearer <access_token>`

**Request**
```json
{
  "refresh_token": "a3f9b2...",
  "all_devices": false
}
```

**Response**
```json
{
  "success": true
}
```

---

#### `GetProfile`

Returns the current profile of a user.

**Request**
```json
{
  "user_id": "a1b2c3d4-..."
}
```

**Response**
```json
{
  "profile": {
    "id": "a1b2c3d4-...",
    "email": "analyst@company.com",
    "role": "ANALYST",
    "mfaEnabled": true,
    "active": true,
    "lastLoginAt": "2026-05-27T14:00:00Z",
    "createdAt": "2026-05-27T12:00:00Z",
    "updatedAt": "2026-05-27T14:00:00Z"
  }
}
```

---

#### `ChangePassword`

**Request**
```json
{
  "user_id": "a1b2c3d4-...",
  "current_password": "OldPassword@123",
  "new_password": "NewPassword@456"
}
```

**Response**
```json
{
  "success": true
}
```

---

### Inter-Service Methods (called by API Gateway)

---

#### `ValidateToken`

The most performance-critical endpoint — target < 2ms. The API Gateway calls this on every inbound request to resolve the caller's identity.

**Request**
```json
{
  "access_token": "eyJhbGci..."
}
```

**Response**
```json
{
  "valid": true,
  "userId": "a1b2c3d4-...",
  "email": "analyst@company.com",
  "role": "ANALYST",
  "permissions": ["alerts:read", "cases:read", "kyc:read", "ml:predict"],
  "expiresAt": "2026-05-27T14:15:00Z"
}
```

**Response (invalid)**
```json
{
  "valid": false,
  "errorCode": "TOKEN_EXPIRED"
}
```

---

#### `GetPermissions`

Returns the permission list for a given role string.

**Request**
```json
{
  "role": "INVESTIGATOR"
}
```

**Response**
```json
{
  "permissions": [
    { "resource": "alerts", "action": "read" },
    { "resource": "alerts", "action": "write" },
    { "resource": "cases",  "action": "read" },
    { "resource": "cases",  "action": "write" }
  ]
}
```

---

### Admin Methods (ADMIN role required)

---

#### `ListUsers`

```json
{
  "page": { "pageSize": 20, "pageToken": "" },
  "role_filter": "ANALYST",
  "active_only": true
}
```

#### `UpdateUser`

```json
{
  "user_id": "a1b2c3d4-...",
  "role": "INVESTIGATOR",
  "active": true
}
```

#### `DeactivateUser`

Marks the user inactive and immediately revokes all active sessions and refresh tokens.

```json
{
  "user_id": "a1b2c3d4-...",
  "reason": "Employee offboarded"
}
```

---

## 5. Security Mechanisms

### Password Hashing — bcrypt cost 12

All passwords are hashed with `bcrypt` at cost factor 12 before storage. At this cost, a single bcrypt comparison takes approximately 250ms on modern hardware. This makes offline dictionary attacks and brute-force infeasible. The raw password never appears in logs, audit events, or error messages.

### JWT Access Tokens — HS256, 15-minute TTL

```
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: {
  "iss": "fraud-detection-system",
  "sub": "<user-id>",
  "iat": <unix timestamp>,
  "exp": <unix timestamp + 900s>,
  "nbf": <unix timestamp>,
  "jti": "<uuid>",        ← unique ID for revocation
  "uid": "<user-id>",
  "email": "<email>",
  "role": "ANALYST",
  "perms": ["alerts:read", "cases:read", ...]
}
Signature: HMACSHA256(base64(header) + "." + base64(payload), JWT_SECRET)
```

Permissions are embedded directly in the token so downstream services do not need to call IAM on every operation.

### JTI Blocklist — Redis O(1) Logout

Because JWTs are stateless, a logout cannot "delete" a token. Instead, the JTI (JWT ID) — a UUID unique to each token — is stored in Redis with a TTL equal to the token's remaining lifetime when `Logout` is called. Every `ValidateToken` call checks this blocklist. This ensures logged-out tokens are rejected within milliseconds.

```
Redis key:   jti:<uuid>
Redis value: "1"
Redis TTL:   remaining lifetime of the token + 1 minute buffer
```

### Refresh Token Security

| Property | Implementation |
|---|---|
| Storage | SHA-256 hash stored in DB, raw token never persisted |
| Entropy | 48 random bytes (384 bits) from `crypto/rand` |
| Rotation | Old token revoked on every refresh call |
| Device binding | `device_id` stored at issuance; mismatch → immediate revoke |
| TTL | 7 days (configurable) |
| Theft detection | Device mismatch is logged as `TOKEN_REVOKED` audit event |

### Rate Limiting — Redis sliding counter

```
Redis key:   ratelimit:login:<email>
Operation:   INCR (atomic) + EXPIRENZ (only sets TTL on key creation)
Window:      15 minutes
Threshold:   5 attempts → LoginResponse returns ACCOUNT_LOCKED error
Reset:       Cleared on successful login
```

`EXPIRENZ` (expire-if-not-exists) is critical: using plain `EXPIRE` would reset the window on every attempt, allowing an attacker to make exactly 4 attempts every 15 minutes forever. `EXPIRENZ` sets the TTL once when the key is created, so the window is fixed from the first attempt.

### Account Lockout — PostgreSQL

In addition to the Redis rate limit, failed password attempts are tracked in `iam.users.failed_attempts`. After 5 failures, `locked_until` is set to `NOW() + 15 minutes`. The lockout is checked before bcrypt comparison, so locked accounts fail fast.

### User Enumeration Protection

The Login endpoint returns `INVALID_CREDENTIALS` for both unknown emails and wrong passwords. An attacker cannot determine whether an email address is registered in the system.

### MFA — TOTP (RFC 6238)

- Secret generated with `pquerna/otp`, 160-bit (SHA-1 base), 30-second window, ±1 step tolerance
- The `otpauth://` URL is safe to encode as a QR code; scanning it with Google Authenticator, Authy, or any RFC 6238 app registers the account
- 8 backup codes are generated at setup, each bcrypt-hashed before storage
- Backup code verification checks all stored hashes to prevent timing attacks

### TLS

In production, gRPC traffic should be terminated at the load balancer or API Gateway with mutual TLS. The service itself does not enforce TLS internally to simplify local development.

---

## 6. RBAC: Roles and Permissions

### Roles

| Role | Description | Intended user |
|---|---|---|
| `ADMIN` | Full system access | System administrator |
| `ANALYST` | Read and triage fraud alerts | Fraud analyst |
| `INVESTIGATOR` | Manage cases, attach evidence | AML investigator |
| `AUDITOR` | Read-only audit trail access | Compliance officer |
| `API_CLIENT` | Machine-to-machine access | Automated systems |

### Permissions Matrix

| Permission | ADMIN | ANALYST | INVESTIGATOR | AUDITOR | API_CLIENT |
|---|---|---|---|---|---|
| `alerts:read` | ✓ | ✓ | ✓ | ✓ | — |
| `alerts:write` | ✓ | — | ✓ | — | — |
| `alerts:delete` | ✓ | — | — | — | — |
| `cases:read` | ✓ | ✓ | ✓ | ✓ | — |
| `cases:write` | ✓ | — | ✓ | — | — |
| `cases:delete` | ✓ | — | — | — | — |
| `kyc:read` | ✓ | ✓ | ✓ | ✓ | — |
| `kyc:write` | ✓ | — | — | — | — |
| `kyc:delete` | ✓ | — | — | — | — |
| `users:read` | ✓ | — | — | ✓ | — |
| `users:write` | ✓ | — | — | — | — |
| `users:delete` | ✓ | — | — | — | — |
| `reports:read` | ✓ | ✓ | ✓ | ✓ | — |
| `reports:generate` | ✓ | — | ✓ | — | — |
| `audit:read` | ✓ | — | — | ✓ | — |
| `ml:predict` | ✓ | ✓ | ✓ | — | — |
| `ml:train` | ✓ | — | — | — | — |
| `blockchain:read` | ✓ | ✓ | ✓ | ✓ | — |
| `blockchain:write` | ✓ | — | ✓ | — | — |

Roles are seeded with fixed UUIDs at database initialisation (`scripts/db/postgres-init.sql`). Permissions are resolved from the database at login time and embedded in the JWT. Downstream services parse permissions from the JWT directly — no further DB lookups needed per request.

---

## 7. Data Storage

### PostgreSQL — `iam` schema

#### `iam.users`

| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key |
| `email` | VARCHAR(255) UNIQUE | Login identifier (stored lowercase) |
| `password_hash` | TEXT | bcrypt hash, cost 12 |
| `role_id` | UUID FK | References `iam.roles` |
| `mfa_enabled` | BOOLEAN | Whether TOTP is active |
| `mfa_secret` | TEXT | TOTP base32 secret |
| `mfa_backup_codes` | JSONB | bcrypt-hashed one-time codes (JSON array) |
| `active` | BOOLEAN | `false` = deactivated account |
| `failed_attempts` | INT | Consecutive failed logins |
| `locked_until` | TIMESTAMPTZ | `NULL` if not locked |
| `last_login_at` | TIMESTAMPTZ | Set on every successful login |
| `last_login_ip` | INET | Last login IP address |

#### `iam.refresh_tokens`

| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID FK | Owner |
| `token_hash` | TEXT UNIQUE | SHA-256 of raw token |
| `device_id` | VARCHAR(255) | Bound device identifier |
| `ip_address` | INET | IP at issuance |
| `user_agent` | TEXT | Browser/app string |
| `expires_at` | TIMESTAMPTZ | Expiry time |
| `revoked_at` | TIMESTAMPTZ | `NULL` if still valid |

#### `iam.audit_log`

| Column | Type | Description |
|---|---|---|
| `id` | BIGSERIAL | Auto-increment |
| `user_id` | UUID FK | Actor (nullable for pre-auth events) |
| `event_type` | VARCHAR(100) | See audit events table |
| `ip_address` | INET | Client IP |
| `user_agent` | TEXT | Client user agent |
| `metadata` | JSONB | Event-specific details |
| `created_at` | TIMESTAMPTZ | Event timestamp |

### Redis — Key Patterns

| Key pattern | Type | TTL | Purpose |
|---|---|---|---|
| `jti:<uuid>` | String | Token remaining lifetime + 1min | JTI blocklist for logout |
| `session:<userID>` | Set | Access TTL + 1min | All active JTIs per user |
| `ratelimit:login:<email>` | String | 15 minutes (set once) | Login attempt counter |
| `mfa_challenge:<uuid>` | String (JSON) | 5 minutes | Pending MFA challenges |

---

## 8. Configuration

All configuration is loaded from environment variables. Copy `.env.example` to `.env` and fill in the required values.

### Required Variables

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `JWT_SECRET` | HMAC signing secret (minimum 32 characters) |
| `REDIS_PASSWORD` | Redis authentication password |

### Full Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `SERVICE_NAME` | `iam-service` | Service identifier in logs and traces |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `IAM_SERVICE_PORT` | `9000` | HTTP port (reserved for future metrics) |
| `IAM_SERVICE_GRPC_PORT` | `50060` | gRPC listener port |
| `POSTGRES_HOST` | `localhost` | PostgreSQL hostname |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `fraud_detection` | Database name |
| `POSTGRES_USER` | `fraud_user` | Database user |
| `POSTGRES_PASSWORD` | — | **Required** |
| `POSTGRES_SSL_MODE` | `disable` | `disable`, `require`, `verify-full` |
| `POSTGRES_MAX_CONN` | `20` | Max connections in pool |
| `POSTGRES_MIN_CONN` | `2` | Min idle connections in pool |
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | — | **Required** |
| `REDIS_DB` | `0` | Redis database index |
| `REDIS_TLS` | `false` | Enable TLS for Redis connection |
| `JWT_SECRET` | — | **Required**, min 32 chars |
| `JWT_ACCESS_TTL` | `15m` | Access token lifetime |
| `JWT_REFRESH_TTL` | `168h` | Refresh token lifetime (7 days) |
| `JWT_ISSUER` | `fraud-detection-system` | JWT `iss` claim value |
| `BCRYPT_COST` | `12` | bcrypt work factor |
| `RATE_LIMIT_LOCKOUT_ATTEMPTS` | `5` | Failed attempts before lockout |
| `RATE_LIMIT_LOCKOUT_DURATION` | `15m` | Lockout duration |
| `MFA_ISSUER` | `FraudDetectionSystem` | TOTP issuer (shown in authenticator apps) |
| `JAEGER_ENDPOINT` | `http://localhost:14268/api/traces` | Jaeger collector endpoint |

---

## 9. Running the Service

### Via Docker Compose (recommended)

```bash
# From the repository root

# 1. Copy and configure environment
cp .env.example .env

# 2. Start infrastructure (postgres + redis)
docker compose up -d postgres redis

# 3. Wait for healthchecks, then start IAM
docker compose up -d iam-service

# 4. Follow logs
docker compose logs -f iam-service

# 5. Check health
docker compose ps iam-service
```

The service container uses the `gcr.io/distroless/static-debian12` runtime image — it has no shell. Health checks use `/grpc_health_probe` which is included in the image.

### First Admin User Bootstrap

The database seed creates roles but no users. The first user registered defaults to `ANALYST`. Promote to `ADMIN` via:

```bash
# Register first user
grpcurl -plaintext \
  -d '{"email":"admin@company.com","password":"Admin@Secure123","role":"ANALYST"}' \
  localhost:50060 fraud.iam.v1.IAMService/Register

# Promote to ADMIN
docker exec fds-postgres psql -U postgres -d fraud_detection -c \
  "UPDATE iam.users
   SET role_id = '00000000-0000-0000-0000-000000000001'
   WHERE email = 'admin@company.com';"
```

Subsequent users can be registered with any role by an authenticated ADMIN via the `Register` RPC.

### Run Tests

```bash
# Unit tests
cd services/iam-service && go test -v -race ./...

# Single test
go test -v -run TestLogin ./internal/service/...
```

### Build Locally

```bash
# From repository root
CGO_ENABLED=0 go build -o iam-service ./services/iam-service/cmd/server/
```

---

## 10. Testing with Postman

Postman supports gRPC natively. The service has server reflection enabled, so Postman can discover all methods automatically.

**Setup (one-time):**
1. Open Postman → **New** → **gRPC Request**
2. Enter URL: `localhost:50060`
3. Click **Use Server Reflection**
4. Select method from the dropdown

**Adding auth header for protected methods:**
In the Postman request, click the **Metadata** tab and add:

| Key | Value |
|---|---|
| `authorization` | `Bearer <your-access-token>` |

### Register
Method: `fraud.iam.v1.IAMService/Register`
```json
{
  "email": "analyst@company.com",
  "password": "Test@Secure123"
}
```

### Login
Method: `fraud.iam.v1.IAMService/Login`
```json
{
  "email": "analyst@company.com",
  "password": "Test@Secure123",
  "device_id": "postman-01",
  "ip_address": "127.0.0.1",
  "user_agent": "PostmanRuntime/7.x"
}
```
Copy the `accessToken` from the response for subsequent calls.

### GetProfile
Method: `fraud.iam.v1.IAMService/GetProfile`
Add `authorization: Bearer <token>` to Metadata tab.
```json
{
  "user_id": "<id-from-login-response>"
}
```

### Logout
Method: `fraud.iam.v1.IAMService/Logout`
Add `authorization: Bearer <token>` to Metadata tab.
```json
{
  "refresh_token": "<refresh-token-from-login>",
  "all_devices": false
}
```

---

## 11. Testing with grpcurl

```bash
export PATH="$HOME/go/bin:$PATH"
ADDR="localhost:50060"

# Health check
grpcurl -plaintext $ADDR grpc.health.v1.Health/Check

# List all methods
grpcurl -plaintext $ADDR list fraud.iam.v1.IAMService

# Register
grpcurl -plaintext -d '{
  "email": "test@company.com",
  "password": "Test@Secure123"
}' $ADDR fraud.iam.v1.IAMService/Register

# Login (save the token)
TOKEN=$(grpcurl -plaintext -d '{
  "email": "test@company.com",
  "password": "Test@Secure123",
  "device_id": "cli-01"
}' $ADDR fraud.iam.v1.IAMService/Login | jq -r .accessToken)

# GetProfile (authenticated)
grpcurl -plaintext \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_id": "<uuid>"}' \
  $ADDR fraud.iam.v1.IAMService/GetProfile

# Logout
grpcurl -plaintext \
  -H "authorization: Bearer $TOKEN" \
  -d '{"all_devices": false}' \
  $ADDR fraud.iam.v1.IAMService/Logout
```

---

## 12. Error Codes

The service returns structured `AuthError` values. The gRPC handler maps them to appropriate status codes.

| Error Code | gRPC Status | Meaning |
|---|---|---|
| `INVALID_CREDENTIALS` | `Unauthenticated` | Wrong email or password |
| `ACCOUNT_LOCKED` | `PermissionDenied` | Too many failed attempts |
| `ACCOUNT_INACTIVE` | `PermissionDenied` | Account has been deactivated |
| `MFA_REQUIRED` | `Unauthenticated` | MFA challenge must be completed |
| `MFA_INVALID` | `Unauthenticated` | Wrong TOTP code or backup code |
| `TOKEN_EXPIRED` | `Unauthenticated` | JWT has passed its expiry time |
| `TOKEN_INVALID` | `Unauthenticated` | JWT signature invalid or malformed |
| `TOKEN_REVOKED` | `Unauthenticated` | Token was explicitly revoked (logout) |
| `EMAIL_ALREADY_REGISTERED` | `AlreadyExists` | Email is taken |
| `USER_NOT_FOUND` | `NotFound` | User ID does not exist |
| `PERMISSION_DENIED` | `PermissionDenied` | Caller lacks required role |
| `PASSWORD_TOO_WEAK` | `InvalidArgument` | Password does not meet policy |
| `INTERNAL_ERROR` | `Internal` | Unexpected server error |

---

## 13. Audit Events

Every security-relevant action is written to `iam.audit_log` with a timestamp, IP address, user agent, and event-specific metadata. The audit log is append-only and is never modified after creation.

| Event Type | Trigger |
|---|---|
| `REGISTER` | New user created |
| `LOGIN_SUCCESS` | Password verified, tokens issued |
| `LOGIN_FAILURE` | Wrong password submitted |
| `LOGIN_LOCKED` | Account locked due to failed attempts |
| `LOGOUT` | Token revoked, optionally all sessions |
| `PASSWORD_CHANGED` | Successful password change |
| `MFA_ENABLED` | MFA setup completed |
| `MFA_VERIFIED` | MFA challenge completed successfully |
| `MFA_FAILED` | Wrong TOTP or backup code submitted |
| `TOKEN_REFRESHED` | Refresh token rotated |
| `TOKEN_REVOKED` | Token revoked (theft detection or explicit logout) |
| `USER_UPDATED` | Role or active status changed by admin |
| `USER_DEACTIVATED` | User account deactivated |

Query recent audit events:
```sql
SELECT event_type, ip_address, metadata, created_at
FROM iam.audit_log
WHERE user_id = '<uuid>'
ORDER BY created_at DESC
LIMIT 50;
```
