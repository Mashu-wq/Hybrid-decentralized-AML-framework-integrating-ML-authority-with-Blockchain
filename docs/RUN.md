# Running the AML Fraud Detection System

Complete, verified run guide for the local development stack.

Project root used throughout:

```bash
cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"
```

---

## 1. What the system is made of

| Layer | Contents |
|---|---|
| **Go microservices** (`services/`) | api-gateway, iam, kyc, transaction, blockchain, alert, case, analytics, encryption — each its own Go module, tied together by `go.work` |
| **Python ML** (`services/ml-service` + `ml/`) | FastAPI on :8000 and gRPC on :50051; RandomForest / XGBoost / LightGBM / GNN / Autoencoder + SHAP & LIME |
| **Blockchain** (`blockchain/`) | Hyperledger Fabric 2.5, 3 orgs (Org1 PrimaryBank, Org2 Regulator, Org3 PartnerBank), 3 channels (kyc / alert / audit), 3 Go chaincodes |
| **Infrastructure** (`docker-compose.yml`) | PostgreSQL, MongoDB, Redis, Kafka + Zookeeper, Vault, Jaeger, Prometheus, Grafana, MLflow, Elasticsearch/Kibana. `dev-tools` profile adds Kafka UI and pgAdmin |
| **Dashboard** (`dashboard/`) | Streamlit, 8 pages, calls the service ports directly (URLs hardcoded in `dashboard/utils/api.py`) |

**End-to-end flow:** `transactions.raw` (Kafka) → transaction-service → ML gRPC scoring → alert-service (writes `fraud_alerts`, anchors to alert-channel) → case-service → blockchain-service (audit receipts with pseudonymized customer IDs) → dashboard.

### Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.22+ (1.25 in use) | |
| Docker + Compose v2 | 24+ / v2.x | |
| Python | 3.11+ (3.12 in use) | venv already provisioned at `dashboard/.venv` |
| Poetry | any | inside `services/ml-service` it resolves to `dashboard/.venv` |
| Fabric binaries | 2.5 | `cryptogen`, `configtxgen`, `peer`, `osnadmin` on `PATH` — optional, only for the blockchain steps |

The Python virtualenv at `dashboard/.venv` already has torch, lightgbm, xgboost, shap, lime, grpcio, streamlit and an editable install of the `ml` package. No `pip install` is needed unless rebuilding from scratch (then: `source dashboard/.venv/bin/activate && pip install -e .`).

---

## 2. Terminal 1 — Infrastructure

```bash
make infra-up
sleep 30
make health          # every line should read OK
```

Starts and exposes:

| Component | Port |
|---|---|
| PostgreSQL | 5433 (host) → 5432 (container) |
| MongoDB | 27017 |
| Redis | 6379 |
| Kafka / Zookeeper | 9092 / 2181 |
| Vault | 8200 (token `dev-root-token`) |
| Jaeger | 16686 |
| Prometheus | 9090 |
| Grafana | 3000 |
| MLflow | 5000 |

Kafka topics (`kyc.events`, `transactions.raw`, `alerts.created`, `audit.events`, `blockchain.events`, `notifications.outbound`) are created automatically by the `kafka-init` container. PostgreSQL runs `scripts/db/postgres-init.sql` automatically, but **only when the data volume is created fresh** — it sets up the `iam`, `kyc`, `alerts`, `cases`, `analytics`, `audit` schemas plus roles and permissions.

If Kafka or Vault shows DOWN, wait another 20 s and re-run `make health`.

Optional visual tools:

```bash
docker compose --profile dev-tools up -d    # Kafka UI :8090, pgAdmin :5050
```

---

## 3. Database migrations (first time on a fresh volume only)

> `make migrate` is **broken** — it looks for `services/*/migrations` and a `cmd/migrate/main.go` that do not exist, and silently does nothing. Apply the SQL by hand.

The services need `kyc.kyc_customers`, `kyc.kyc_pii`, `kyc.kyc_documents`, `fraud_alerts`, `investigation_cases` and the analytics views, which `postgres-init.sql` does not fully create.

Check whether the migrations are already applied:

```bash
export PGPASSWORD=iam_user
psql -h localhost -p 5433 -U fraud_user -d fraud_detection \
  -c '\dt kyc.*' -c '\dt public.fraud_alerts'
```

If the tables are missing, apply all four files in order:

```bash
export PGPASSWORD=iam_user
PSQL="psql -h localhost -p 5433 -U fraud_user -d fraud_detection"

$PSQL -f scripts/db/migrations/001_kyc_schema.sql
$PSQL -f services/alert-service/scripts/db/migrations/002_alert_schema.sql
$PSQL -f services/case-service/scripts/db/migrations/003_case_schema.sql
$PSQL -f services/analytics-service/scripts/db/migrations/004_analytics_views.sql
```

`001_kyc_schema.sql` uses bare `CREATE TABLE` (no `IF NOT EXISTS`), so re-running it against an already-migrated database errors out. Files 002, 003 and 004 are idempotent.

DB credentials: `host=localhost port=5433 db=fraud_detection user=fraud_user password=iam_user`.

---

## 4. Seed demo data

```bash
make seed
```

Runs `scripts/seed-data.sh` (idempotent). Creates:

| User | Role | Password |
|---|---|---|
| `admin@fraud.local` | ADMIN | `FraudOps@2026` |
| `analyst@fraud.local` | ANALYST | `FraudOps@2026` |
| `investigator@fraud.local` | INVESTIGATOR | `FraudOps@2026` |
| `auditor@fraud.local` | AUDITOR | `FraudOps@2026` |

Plus 5 KYC customers (APPROVED / PENDING / REJECTED across LOW→CRITICAL risk), sample alerts and cases.

---

## 5. Terminal 2 — All services

```bash
make run
```

Runs `scripts/run-all.sh`, which starts everything in dependency order (encryption first, gateway last) and writes logs to `logs/<service>.log`:

| Service | HTTP | gRPC |
|---|---|---|
| encryption-service | — | 50066 |
| iam-service | 9000 | 50060 |
| kyc-service | 9001 | 50061 |
| transaction-service | 9002 | 50062 |
| alert-service | 9003 | 50063 |
| case-service | 9004 | 50064 |
| blockchain-service | 9005 | 50065 |
| analytics-service | 9006 | — |
| ml-service (Python) | 8000 | 50051 |
| api-gateway | 8080 | — |

`Ctrl+C` stops all of them (the script traps EXIT and kills every child).

> **Always use `make run`, never `bash scripts/run-all.sh` directly.**
> No Go service loads `.env` itself. The variables only reach the processes because the Makefile does `-include .env` followed by `export`. Invoking the script directly leaves them unexported, and services fall back to defaults (e.g. PostgreSQL 5432 instead of 5433) and fail to connect.

Poetry inside `services/ml-service` resolves to `dashboard/.venv`, so the ML service picks up the correct interpreter automatically. Models load from the pre-trained artifacts in `ml/artifacts/`. The gRPC server on :50051 starts from the FastAPI startup event, so both `python main.py` and `uvicorn main:app` bring it up.

To run a single service for debugging:

```bash
make run-svc SVC=kyc-service
tail -f logs/kyc-service.log
```

Rebuild binaries after changing Go source:

```bash
make build                      # all services → bin/
make build-svc SVC=kyc-service  # one service
```

---

## 6. Terminal 3 — Dashboard

```bash
source dashboard/.venv/bin/activate
streamlit run dashboard/app.py
```

Opens at <http://localhost:8501>.

---

## 7. Terminal 4 — Hyperledger Fabric (optional)

Only needed for the Blockchain Audit page and on-chain KYC/alert anchoring. Everything else works without it — `blockchain-service` falls back to its stub.

```bash
make fabric-up          # 3 orgs, 6 peers + CouchDB, 3 RAFT orderers, 3 channels
make chaincode-deploy   # kyc-contract, alert-contract, audit-contract
curl -s localhost:9005/health | python3 -m json.tool
make fabric-down        # when finished
```

Two current caveats:

- **`audit-contract` now ships `collections_config.json`** (private data collections). `deploy-chaincode.sh` detects it and passes `--collections-config` automatically. On a **fresh** network the default v1.0 / sequence 1 is correct. Against an audit-contract that is **already committed** on the channel, the definition must be bumped:

  ```bash
  CHAINCODE_VERSION=1.1 CHAINCODE_SEQUENCE=2 \
    bash blockchain/network/deploy-chaincode.sh audit-contract audit-channel
  ```

- **`.env` is missing two blockchain privacy variables** that exist in `.env.example`. They currently fall back to insecure dev defaults — add them so pseudonyms stay stable across restarts:

  ```
  BLOCKCHAIN_CUSTOMER_HMAC_KEY=<pick a secret, keep it stable>
  BLOCKCHAIN_AUDIT_PRIVATE_ORGS=Org1MSP,Org2MSP
  ```

  `BLOCKCHAIN_AUDIT_PRIVATE_ORGS` must match the policy in `blockchain/chaincode/audit-contract/collections_config.json`.

---

## 8. Verify end to end

```bash
make health
curl -s localhost:8000/health | python3 -m json.tool   # ML: loaded_models
curl -s localhost:9006/health | python3 -m json.tool   # analytics: mongo + postgres
curl -s localhost:9005/health | python3 -m json.tool   # blockchain: channel block heights
curl -s localhost:8080/health | python3 -m json.tool   # gateway → all downstream

# ML benchmark metrics (works even without live models)
curl -s localhost:8000/api/v1/model/comparison | python3 -m json.tool

docker ps --format "table {{.Names}}\t{{.Status}}"
```

Drive a transaction through the full pipeline:

```bash
./scripts/publish_tx.sh "$(cat scripts/test-data/tx_suspicious.json)"
# also available: tx_normal.json, tx_critical.json
tail -f logs/transaction-service.log logs/alert-service.log
```

---

## 9. Access points

| Service | URL | Credentials |
|---|---|---|
| Dashboard | http://localhost:8501 | — |
| API Gateway | http://localhost:8080 | JWT from `/auth/login` |
| ML Service (REST) | http://localhost:8000 | Swagger at `/docs` |
| Analytics Service | http://localhost:9006 | — |
| Grafana | http://localhost:3000 | admin / `changeme_grafana_password` |
| Prometheus | http://localhost:9090 | — |
| Jaeger | http://localhost:16686 | — |
| MLflow | http://localhost:5000 | — |
| Vault UI | http://localhost:8200 | token `dev-root-token` |
| Kafka UI | http://localhost:8090 | needs `--profile dev-tools` |
| pgAdmin | http://localhost:5050 | needs `--profile dev-tools` |

---

## 10. Shutdown

```bash
# Ctrl+C in the service and dashboard terminals
make fabric-down     # if Fabric was started
make infra-down      # stops containers, keeps data volumes
make infra-clean     # stops containers AND deletes all volumes (destructive)
```

---

## 11. Make targets that do not work — do not run them

| Target | Problem |
|---|---|
| `make migrate` / `migrate-down` / `migrate-status` | Wrong paths; no `cmd/migrate/main.go` exists. Use section 3. |
| `make seed-ml` | Calls `ml/data/download_elliptic.py` and `ml/data/preprocess.py`, neither exists. |
| `make ml-train` | Calls `models.train_all`, which does not exist. |
| `make ml-evaluate` | Calls `evaluation.evaluate_all`, which does not exist (`ml/evaluation/evaluator.py` is the real module). |
| `make docs` / `docs-serve` | Reference `docs/api-spec.yaml`, which is not present. |

**Retraining is not required.** `ml/artifacts/` already holds the trained models (`random_forest_model.pkl`, `xgboost_model.pkl`, `lightgbm_model.pkl`, `gnn_model.pt`, `autoencoder_model.pt`, `ensemble.json`, `background_sample.npy`). `ml/data/raw/` and `ml/data/processed/` are empty, so retraining would first require re-downloading the Elliptic dataset.

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard shows "service unavailable" | The service died at startup — check `logs/<service>.log`, usually a DB or env-var problem. |
| KYC / Alert / Case endpoints return 500 | Migrations from section 3 were not applied. |
| PostgreSQL connection refused | Containers not up: `make infra-up`. Confirm the host port is 5433, not 5432. |
| Kafka errors in transaction-service | Kafka needs ~60 s after `make infra-up`. The ML gRPC dial is non-blocking and auto-reconnects, so it recovers on its own. |
| ML service: `No module named 'ml'` | `source dashboard/.venv/bin/activate && pip install -e .` from the project root. |
| ML service: GNN `state_dict` mismatch | Known checkpoint issue. The service still starts; only the GNN model is unavailable. |
| Blockchain page shows "service offline" | Start Fabric (section 7). Optional — every other page works without it. |
| `Port already in use` | `ss -tlnp \| grep <port>` then `kill <pid>`. |
| Services connect to the wrong ports/DB | You ran `scripts/run-all.sh` directly instead of `make run` — see the note in section 5. |

---

## 13. Summary — the short version

```bash
cd "/home/mayesha-marzia-zaman/AML_fraud_detection (2)/AML_fraud_detection"

# Terminal 1
make infra-up && sleep 30 && make health
# first time only: apply the 4 migrations (section 3), then:
make seed

# Terminal 2
make run

# Terminal 3
source dashboard/.venv/bin/activate && streamlit run dashboard/app.py

# Terminal 4 (optional)
make fabric-up && make chaincode-deploy
```

Open <http://localhost:8501>.



















































Authoritative counts confirmed from two independent sources (figure + model metadata). Test set is 9,642 with 506 illicit. Computing the derived metrics exactly.

  Ran 1 shell command

Now applying all the unambiguous fixes in one verified pass.
  Ran 1 shell command

Now applying all the unambiguous fixes in one verified pass.

  Ran 1 shell command

All 20 applied. Verifying, and tightening one narrative phrase that the new numbers changed.

  Ran 2 shell commands

Fixed and verified. Table IV now carries the authoritative counts (cross-checked against both the confusion-matrix figure and the model metadata), and
every derived metric recomputes correctly from them.

Applied — 21 edits, all verified

┌─────┬───────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  #  │                  Fix                  │               Before → After                                             │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1   │ Broken \ref (would print literally in │ Section~⏎ef{...} → Section~\ref{sec:features}                                                         │
│     │  the PDF)                             │                                                                          │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2   │ Feature mapping, 3 places             │ 38 populated / 47 padded → 29 / 56                                                                    │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3   │ Test partition                        │ 9,643 tx, 503 5.25%                                                      │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4   │ Table IV, all 3 rows                  │ see below                                                                │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 5   │ Results narrative                     │ RF "42 FP, misof 506; LGBM "328 at 161 FP" → 345 at 189 FP; "175 of 503  │
│     │                                       │ unflagged" → 161 of 506                                                                               │
├─────┼───────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ 6   │ Weber comparison                      │ "reaches 0.685, close to" → 0.692, essentially matching their local-feature result                    │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 7   │ Abstract                              │ 65.2% recall @                                                           │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 8   │ Conclusion                            │ 65.21% @ 0.9633 → 68.18% @ 0.9649                                                                     │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 9   │ Table V timing column                 │ 38.9/37.2/36.6re-measured)                                               │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 10  │ Timing prose                          │ "36–39 μs" → "                                                           │
├─────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 11  │ PDC name in Algorithm 1               │ auditTxDetails                                                           │
└─────┴───────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────┘

New Table IV:
LightGBM       96.37  64.61  68.18  66.35  0.9649  0.645   8947  189  161  345
Random Forest  97.34  88.34  56.92  69.23  0.9638  0.697   9098   38  218  288
XGBoost        96.69  70.64  63.24  66.74  0.9597  0.651   9003  133  186  320
All three rows sum to 9,642 and recompute exactly to the stated accuracy/precision/recall/F1/MCC. I recomputed MCC from the new counts rather than
carrying the old values.

Two knock-on edits the new numbers forced: XGBoost is no longeower recall" than LightGBM (it now has higher precision, lowerrecall), so that clause became "between them on both axes"; and RF's F1 rising to 0.692 makes it essentially equal to Weber's 0.694 local-feature baseline
rather than merely "close" — which actually strengthens your §

Backup of the original is at scratchpad/paper.bak.

Three items remaining

- Decide the τ ladder (§III-D / Eq. 1). Still says 0.70/0.55/0.40/0.25; deployed is 0.70/0.55/0.008/0.005. This is the one mismatch that changes a claim
rather than a number, and it's coupled to the next item — I di direction is defensible and the choice is yours. Note thatwith the current degenerate serving score (p ≈ 0.0078), the paper's published values would mean nothing ever alerts.
- Production-scorer claim (line 659): paper says LightGBM was 32 is active_model = "ensemble". Switching the config tolightgbm to match the paper would drop the served score to ~3.7e-7 and stop alerting entirely — so resolve this together with the thresholds.
- Clear the three \TODOs: the BAML row in Table I (×3 cells), n §VI-A, and the commit-latency figures in §VI-D. Your own file header says not to submit while any remain.