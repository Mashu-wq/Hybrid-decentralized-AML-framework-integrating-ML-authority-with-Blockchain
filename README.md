# Hybrid Decentralized AML Framework Integrating ML Authority With Blockchain Auditability
# Core Microservices
- ## API Gateway Service
- ## Identity And Access Management Service
- ## KYC Service
- ## Transaction Monitoring
- ## ML Service
- ## Blockchain Service
- ## Alert & Notification Service
- ## Investigation & Case  management Service
- ## Analytics & Reporting Service
- ## Data Encryption Service
  
### 🎯 What is IAM Service in my system?
IAM is not just login & signup. It is the trust root of my whole architecture. IAM has its own isolated database schema inside PostgreSQL. It must NOT share tables with KYC or Transaction DB.
<img width="912" height="2735" alt="iam" src="https://github.com/user-attachments/assets/400ed300-9854-4e7f-8f93-971f6fcac716" />

## 🗃 IAM Core Tables
### users

| field         | purpose                       |
| ------------- | ----------------------------- |
| id (UUID)     | unique identity               |
| email         | login                         |
| password_hash | bcrypt                        |
| role          | admin / investigator / client |
| mfa_enabled   | true/false                    |
| created_at    | audit                         |

### refresh_tokens
| field      | purpose         |
| ---------- | --------------- |
| id         | token id        |
| user_id    | FK users        |
| token_hash | SHA-256         |
| expires_at | session timeout |

### audit_logs
| field      | purpose              |
| ---------- | -------------------- |
| id         | event id             |
| user_id    | actor                |
| event      | LOGIN_SUCCESS / FAIL |
| ip_address | trace                |
| timestamp  | forensic             |

### mfa_secrets
| field        | purpose   |
| ------------ | --------- |
| user_id      | FK        |
| totp_secret  | encrypted |
| backup_codes | hashed    |

### IAM Data Flow
Register → Hash password → Save to iam_schema.users

Login → Verify → Write audit_logs

JWT → Stateless → No DB

Refresh → refresh_tokens table

### What is Middleware?
Middleware is a gatekeeper function that runs:
before protected APIs are executed.

### It checks:
- Is the request authenticated?
- Is the JWT valid?
- Does the user have permission?

### Without middleware
``` POST /admin/deleteUser ```
Anyone can call it.

### With middleware
``` Request → Middleware → API Handler ```
Middleware blocks unauthorized users before code execution.

## What middleware.go does in my IAM service?

Client Request
     │
     ▼
AuthMiddleware()
     │
     ├─ Extract Bearer token
     ├─ Verify JWT signature
     ├─ Decode claims (role, id)
     ├─ Inject identity into context
     ▼
Protected Handler runs

### Real-life analogy
- Middleware is like the security guard at bank gate.
- No ID → No entry.


