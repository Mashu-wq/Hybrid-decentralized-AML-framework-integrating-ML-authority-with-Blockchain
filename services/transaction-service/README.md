# Transaction Monitoring Service

Real-time fraud detection pipeline for financial transactions. Consumes raw transactions from Kafka, extracts behavioral/geographic/ML features, obtains fraud predictions from the ML Service via gRPC, and publishes alerts to the Alert Service.

## Architecture

```
Kafka (transactions.raw)
        │
        ▼
  Kafka Consumer (worker pool)
        │
        ▼
  Feature Extractor
  ├── Temporal features (hour, day-of-week, time-since-last-tx)
  ├── Velocity features (Redis sorted sets — 1h/24h/7d/30d windows)
  ├── Geographic features (country risk, cross-border, country-change-2h)
  ├── Merchant features (MCC risk score, high-risk flag)
  └── KYC features (customer risk profile from Redis cache)
        │
        ▼
  ML Service gRPC (PredictFraud)
  └── Heuristic fallback when ML service unavailable
        │
        ▼
  ┌─────────────────────────────────────┐
  │  Fraud probability > 0.7?           │
  │  Yes → Kafka (alerts.created)       │
  │  No  → skip                         │
  └─────────────────────────────────────┘
        │
        ▼
  MongoDB (time-series: enriched_transactions)
  Redis   (5-min TTL risk score cache)
        │
        ▼
  gRPC Server (TransactionService)
  ├── IngestTransaction (sync + async modes)
  ├── IngestBatch       (up to 500 transactions)
  ├── GetTransaction    (by tx_hash)
  ├── GetCustomerHistory (paginated, filterable)
  ├── GetRiskScore      (cached 5 min)
  ├── GetFeatures       (stored feature vector)
  ├── GetVelocityStats  (real-time Redis aggregates)
  └── HealthCheck
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVICE_NAME` | `transaction-service` | Service identifier in logs/traces |
| `ENVIRONMENT` | `development` | Environment name |
| `LOG_LEVEL` | `info` | Log level: debug/info/warn/error |
| `TRANSACTION_SERVICE_GRPC_PORT` | `50062` | gRPC listen port |
| `INTERNAL_JWT_SECRET` | **required** | Shared HMAC secret for service-to-service JWT |
| `KAFKA_BROKERS` | `localhost:9092` | Comma-separated Kafka broker list |
| `TRANSACTIONS_RAW_TOPIC` | `transactions.raw` | Topic to consume |
| `ALERTS_CREATED_TOPIC` | `alerts.created` | Topic to publish alerts |
| `KAFKA_CONSUMER_GROUP` | `transaction-service-cg` | Consumer group ID |
| `KAFKA_WORKERS` | `8` | Number of parallel Kafka message processors |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `MONGO_DB` | `fraud_detection` | MongoDB database name |
| `MONGO_TX_COLLECTION` | `enriched_transactions` | Time-series collection name |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | `` | Redis password (empty = no auth) |
| `REDIS_DB` | `0` | Redis DB index |
| `ML_SERVICE_ADDR` | `localhost:50065` | ML Service gRPC address |
| `ML_SERVICE_TIMEOUT_SEC` | `5` | ML prediction timeout in seconds |
| `FRAUD_ALERT_THRESHOLD` | `0.7` | Publish alert if fraud_prob > this |
| `VELOCITY_ALERT_1H_LIMIT` | `20` | Alert if tx count in 1h exceeds this |
| `VELOCITY_ALERT_24H_LIMIT` | `100` | Alert if tx count in 24h exceeds this |
| `JAEGER_ENDPOINT` | `http://localhost:14268/api/traces` | Jaeger tracing endpoint |
| `PIPELINE_VERSION` | `1.0.0` | Feature pipeline version string |

## Redis Key Schema

| Key | Type | TTL | Description |
|-----|------|-----|-------------|
| `vel:{customerID}:records` | Sorted Set | 31 days | Transaction velocity records (score=unix_ms, member=JSON) |
| `last_tx:{customerID}` | String (JSON) | 48h | Most recent transaction metadata |
| `customer:profile:{customerID}` | Hash | 24h | KYC risk profile cache |
| `countries:{customerID}:2h` | Sorted Set | 3h | Recent country codes (country-change feature) |
| `risk:{customerID}` | String (JSON) | 5 min | Cached risk score |

## MongoDB Schema

Collection: `enriched_transactions` (time-series)
- **timeField**: `processed_at`
- **metaField**: `customer_id`
- **granularity**: `seconds`
- **expireAfterSeconds**: `7776000` (90 days)

## Local Development

```bash
# Start infrastructure
docker-compose up -d mongo redis kafka

# Run service
export INTERNAL_JWT_SECRET="dev-secret-must-be-32-chars-min!!"
export POSTGRES_PASSWORD=fraud_pass   # not used by tx-service but config helper needs it
go run ./services/transaction-service/cmd/server

# Send a test transaction via gRPC (grpcurl)
grpcurl -plaintext -d '{
  "transaction": {
    "tx_hash": "abc123",
    "customer_id": "cust-001",
    "amount": 9999.99,
    "currency_code": "USD",
    "country_code": "KP",
    "merchant_category": "cryptocurrency",
    "transaction_at": "2026-04-01T12:00:00Z"
  },
  "sync": true
}' localhost:50062 fraud.transaction.v1.TransactionService/IngestTransaction
```

## Testing

```bash
cd services/transaction-service
go test ./internal/service/... -v -count=1
```

## gRPC API

Service: `fraud.transaction.v1.TransactionService`  
Port: `50062`

| Method | Auth | Description |
|--------|------|-------------|
| `IngestTransaction` | Public | Ingest single transaction (sync or async) |
| `IngestBatch` | Public | Ingest up to 500 transactions asynchronously |
| `GetTransaction` | JWT | Retrieve enriched transaction by tx_hash |
| `GetCustomerHistory` | JWT | Paginated transaction history |
| `GetRiskScore` | JWT | Current risk score (5-min cache) |
| `GetFeatures` | JWT | Stored feature vector |
| `GetVelocityStats` | JWT | Real-time velocity statistics |
| `HealthCheck` | Public | Service health status |

## Alert Thresholds

| Risk Level | Fraud Probability | Action |
|------------|-------------------|--------|
| LOW | < 0.5 | Store only |
| MEDIUM | 0.5 – 0.7 | Store only |
| HIGH | 0.7 – 0.85 | → alerts.created Kafka topic |
| CRITICAL | > 0.85 | → alerts.created Kafka topic |
