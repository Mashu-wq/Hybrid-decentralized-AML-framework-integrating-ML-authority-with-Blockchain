# KYC Service

Go service responsible for customer onboarding, document OCR, biometric verification, encrypted PII handling, Kafka event publishing, and blockchain-service registration triggers.

## Responsibilities

- Register customers and encrypt all PII through the encryption service before persistence
- Accept KYC document submissions and run OCR via AWS Textract or a local mock
- Verify selfie-to-document face match through the ML service gRPC client or a local mock
- Publish `KYC_REGISTERED` and status change events to Kafka
- Trigger blockchain-service registration and status anchoring

## Key Environment Variables

- `KYC_SERVICE_PORT`
- `KYC_SERVICE_GRPC_PORT`
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `KAFKA_BROKERS`
- `KYC_EVENTS_TOPIC`
- `ENCRYPTION_SERVICE_ADDR`
- `BLOCKCHAIN_SERVICE_ADDR`
- `ML_SERVICE_ADDR`
- `USE_MOCK_TEXTRACT`
- `USE_MOCK_FACE_MATCH`
- `USE_STUB_BLOCKCHAIN`
- `DOCUMENT_UPLOAD_DIR`
- `MAX_UPLOAD_SIZE_BYTES`

## API Notes

- `POST /api/v1/kyc/customers` registers a customer
- `POST /api/v1/kyc/customers/{id}/documents` accepts either JSON with a stored object key or `multipart/form-data` with a `file` field
- `POST /api/v1/kyc/customers/{id}/face-verify` runs biometric verification
- `PATCH /api/v1/kyc/customers/{id}/status` updates KYC status

## Local Development

Use mock OCR and mock face matching for local runs:

```bash
USE_MOCK_TEXTRACT=true
USE_MOCK_FACE_MATCH=true
USE_STUB_BLOCKCHAIN=true
```
