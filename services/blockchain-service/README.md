# Blockchain Service

The blockchain service is the Hyperledger Fabric integration point for the platform.

Responsibilities:

- invoke `kyc-contract`, `alert-contract`, and `audit-contract`
- pool Fabric channel clients for lower invocation latency
- subscribe to chaincode events and forward them to Kafka
- expose internal REST endpoints used by downstream services
- expose `/health` connectivity checks against peer and orderer access

Main endpoints:

- `POST /internal/v1/kyc/register`
- `POST /internal/v1/kyc/status`
- `GET /internal/v1/kyc/record/{customerID}`
- `POST /internal/v1/alerts/create`
- `POST /internal/v1/alerts/status`
- `POST /internal/v1/audit/investigator-action`
- `POST /internal/v1/audit/model-prediction`
- `GET /health`

Key environment variables:

- `BLOCKCHAIN_CONNECTION_PROFILE`
- `BLOCKCHAIN_ORG_NAME`
- `BLOCKCHAIN_USERNAME`
- `BLOCKCHAIN_POOL_SIZE`
- `BLOCKCHAIN_KYC_CHANNEL`
- `BLOCKCHAIN_ALERT_CHANNEL`
- `BLOCKCHAIN_AUDIT_CHANNEL`
- `BLOCKCHAIN_KYC_CHAINCODE`
- `BLOCKCHAIN_ALERT_CHAINCODE`
- `BLOCKCHAIN_AUDIT_CHAINCODE`
- `KAFKA_BROKERS`
- `BLOCKCHAIN_EVENT_TOPIC`
