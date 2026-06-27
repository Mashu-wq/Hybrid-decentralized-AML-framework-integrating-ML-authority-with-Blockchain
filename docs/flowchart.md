# System Flowcharts

> Decision-level flowcharts for the Blockchain-Based KYC/AML Fraud Detection
> platform. These show the **runtime logic and branch points** (the *what happens
> when* ), complementing the component diagrams in `archi.md`. All diagrams are
> Mermaid and render on GitHub.

Contents:
1. [End-to-end system flow](#1-end-to-end-system-flow)
2. [KYC onboarding flow](#2-kyc-onboarding-flow)
3. [Transaction processing pipeline](#3-transaction-processing-pipeline)
4. [Composite risk score & alert-level decision](#4-composite-risk-score--alert-level-decision)
5. [Alert ingestion & blockchain anchoring](#5-alert-ingestion--blockchain-anchoring)
6. [Case management & SAR flow](#6-case-management--sar-flow)
7. [Blockchain audit & compliance verification](#7-blockchain-audit--compliance-verification)
8. [ML inference flow](#8-ml-inference-flow)

---

## 1. End-to-end system flow

The full happy path from customer onboarding to regulator verification.

```mermaid
flowchart TD
    A([Customer onboarded]) --> B[KYC Service:<br/>register + approve]
    B --> C[(kyc-channel:<br/>identity hash + risk tier)]
    C --> D[kyc.events to Kafka]
    D --> E[Transaction Service:<br/>cache KYC risk profile in Redis]

    F([Transaction arrives<br/>Kafka transactions.raw]) --> G[Transaction Service:<br/>extract features + ML score]
    E -. risk tier used .-> G
    G --> H[Composite risk score]
    H --> I{fraud_prob &gt;<br/>KYC-tier threshold?}
    I -- yes --> J[Publish AlertEvent<br/>Kafka alerts.created]
    I -- no --> K[No alert]
    G --> L[(audit-channel:<br/>TRANSACTION_PROCESSED<br/>receipt for EVERY tx)]

    J --> M[Alert Service:<br/>persist + notify]
    M --> N[(alert-channel:<br/>CreateAlert + riskLevel)]
    M --> O[Investigator opens case]
    O --> P[Case Service:<br/>investigate + generate SAR]
    P --> Q[(audit-channel:<br/>SAR_FILED hash +<br/>INVESTIGATOR_ACTION)]

    R([Regulator / Org2]) --> S[Pull compliance report<br/>from own peer]
    L -. independently verifiable .-> S
    N -. .-> S
    Q -. .-> S
    S --> T([Tamper-evident audit<br/>— no trust in bank required])
```

---

## 2. KYC onboarding flow

How a customer's identity and risk tier become tamper-evident on-chain, and how that
tier reaches the live fraud pipeline.

```mermaid
flowchart TD
    A([POST /kyc/customers]) --> B[Validate input]
    B --> C[Compute SHA-256 of document<br/>— raw PII never leaves service]
    C --> D[Encryption Service:<br/>AES-256-GCM encrypt PII via Vault]
    D --> E[(PostgreSQL:<br/>customer row, status PENDING)]
    E --> F[(kyc-channel:<br/>RegisterCustomer, identity hash)]
    F --> G([customer_id returned])

    G --> H([PATCH /status APPROVED + risk_level])
    H --> I[(kyc-channel:<br/>UpdateKYCStatus + risk tier)]
    I --> J{on-chain status<br/>== APPROVED?}
    J -- not yet --> K[retry 6x with backoff<br/>race-safe]
    K --> J
    J -- yes --> L[Publish to Kafka kyc.events]
    L --> M[Transaction Service consumer:<br/>map LOW=1..CRITICAL=4]
    M --> N[(Redis: SetCustomerProfile<br/>risk score + tier, TTL)]
    N --> O([Threshold now active for<br/>this customer's next tx])
```

---

## 3. Transaction processing pipeline

The core `ProcessTransaction` logic in the Transaction Service. Every step after
feature extraction is non-blocking on its own failure.

```mermaid
flowchart TD
    A([Kafka transactions.raw]) --> B[Step 1: Validate raw tx]
    B -->|invalid| B1[Reject + DLQ]
    B -->|valid| C[Step 2: Extract features]

    C --> C1[Redis lookups:<br/>velocity, last_tx, KYC profile,<br/>country history, amount avg]
    C1 --> D[Step 3: ML PredictFraud gRPC]
    D --> D1{ML service<br/>reachable?}
    D1 -- no --> D2[Heuristic fallback prediction]
    D1 -- yes --> D3[fraud_probability + SHAP]
    D2 --> E
    D3 --> E[Step 4: compositeRiskScore<br/>ML 10% + KYC/merchant/geo 30% + bonuses]

    E --> F[Step 5: Update Redis<br/>velocity sorted sets + risk score 5-min TTL]
    F --> G{fraud_probability &gt;<br/>threshold for KYC tier?}
    G -- yes --> H[Build AlertEvent<br/>fraud_prob + composite risk_score + SHAP]
    H --> H1[Publish to Kafka alerts.created]
    G -- no --> I[No alert<br/>alertFired=false]
    H1 --> J
    I --> J[Step 6: Persist enriched tx to MongoDB]

    J --> K[Step 7: Anchor receipt<br/>fire-and-forget, non-blocking]
    K --> L[(audit-channel:<br/>RecordTransactionProcessed<br/>alertFired flag included)]
    L --> M([Pipeline complete])
```

**KYC-tier thresholds (fraud_prob must exceed to alert):**

```mermaid
flowchart LR
    T0[KYC tier] --> T1[LOW &rarr; 0.70]
    T0 --> T2[MEDIUM &rarr; 0.55]
    T0 --> T3[HIGH &rarr; 0.008]
    T0 --> T4[CRITICAL &rarr; 0.005]
```

---

## 4. Composite risk score & alert-level decision

How the hybrid score is computed and mapped to the on-chain risk level (alert-contract v1.1).

```mermaid
flowchart TD
    A([Extracted features + fraud_prob]) --> B[base = 0.10 &times; fraud_prob&times;100]
    B --> C[+ 0.30 &times; CustomerRiskScore<br/>KYC tier: LOW20 MED50 HIGH80 CRIT95]
    C --> D[+ 0.30 &times; MerchantRiskScore<br/>gambling90 crypto75 transfer68 default15]
    D --> E[+ 0.30 &times; GeographicRiskScore<br/>IR95 RU72 KY50 US10]
    E --> F{cross-border?}
    F -- yes --> F1[+12]
    F -- no --> G
    F1 --> G{amount anomalous?}
    G -- yes --> G1[+ up to 12]
    G -- no --> H
    G1 --> H{high-risk merchant?}
    H -- yes --> H1[+6]
    H -- no --> I
    H1 --> I[clamp to 0..100<br/>= compositeRiskScore]

    I --> J{riskScore &gt; 85?}
    J -- yes --> J1([CRITICAL])
    J -- no --> K{riskScore &ge; 70?}
    K -- yes --> K1([HIGH])
    K -- no --> L{riskScore &ge; 50?}
    L -- yes --> L1([MEDIUM])
    L -- no --> M1([LOW])
```

---

## 5. Alert ingestion & blockchain anchoring

The Alert Service `IngestAlert` flow, including the alert-channel anchoring added this iteration.

```mermaid
flowchart TD
    A([Kafka alerts.created]) --> B[Validate event]
    B --> C{duplicate?<br/>Redis dedup check}
    C -- yes --> C1[Discard]
    C -- no --> D[(PostgreSQL:<br/>insert alert, status OPEN)]
    D --> E{unique-constraint<br/>violation?}
    E -- yes --> E1[Evict Redis key + discard<br/>another worker won]
    E -- no --> F[Send notifications<br/>email/SMS/Slack/webhook — non-fatal]
    F --> G[WebSocket broadcast<br/>to dashboards]

    D --> H[Anchor on alert-channel<br/>goroutine, fire-and-forget]
    H --> I[(alert-channel:<br/>CreateAlert &rarr; deriveRiskLevel)]
    I --> J{returned Fabric txId?}
    J -- yes --> K[(PostgreSQL:<br/>back-fill blockchain_tx_id)]
    J -- no --> L[Log warning<br/>alert persisted, retry later]
```

---

## 6. Case management & SAR flow

From alert to a closed case with a tamper-evident SAR. Case status transitions are
enforced by the domain state machine.

```mermaid
flowchart TD
    A([Alert reviewed]) --> B[POST /cases<br/>status OPEN]
    B --> C[(audit-channel:<br/>INVESTIGATOR_ACTION CASE_CREATED)]
    C --> D[PATCH status &rarr; IN_REVIEW]
    D --> E[Add evidence<br/>S3 presign — non-fatal locally]
    E --> F[Record investigator action]
    F --> G[(audit-channel:<br/>EVIDENCE_REVIEWED)]
    G --> H[POST /sar generate SAR]
    H --> I[Compute SHA-256 of PDF up front]
    I --> J{S3 upload OK?}
    J -- yes --> K[PDF stored in S3]
    J -- no --> K1[Upload skipped<br/>non-fatal]
    K --> L
    K1 --> L[(audit-channel:<br/>SAR_FILED with sarHash)]
    L --> M[PATCH status &rarr; CLOSED<br/>resolution summary]
    M --> N([Case closed])

    subgraph SM[Valid case transitions]
        S1[OPEN] --> S2[IN_REVIEW]
        S2 --> S3[PENDING_SAR]
        S3 --> S4[CLOSED]
        S1 -.-> S5[ESCALATED]
        S2 -.-> S5
        S5 -.-> S2
        S5 -.-> S4
    end
```

---

## 7. Blockchain audit & compliance verification

How a regulator independently verifies the audit trail — the fabrication-gap-closure check.

```mermaid
flowchart TD
    A([Regulator query]) --> B{query type}
    B -->|by transaction| C[GetAuditTrail<br/>entity_type=TRANSACTION, tx_hash]
    B -->|by case| D[GetAuditTrail<br/>entity_type=CASE, case_id]
    B -->|date range| E[GetComplianceReport<br/>start, end]

    C --> F{TRANSACTION_PROCESSED<br/>receipt present?}
    F -- yes --> F1([Transaction was screened<br/>— verified]) 
    F -- no --> F2([Receipt MISSING<br/>&rarr; suppression detectable])

    D --> G[SAR_FILED + INVESTIGATOR_ACTION records]
    G --> H[Re-hash SAR PDF and compare<br/>to on-chain sarHash]
    H --> I{hashes match?}
    I -- yes --> I1([Document integrity verified])
    I -- no --> I2([Document altered after filing])

    E --> J[Totals: events, tx processed,<br/>SARs filed, investigator actions]
    J --> K([Pulled from regulator's OWN peer<br/>— no trust in bank required])
```

---

## 8. ML inference flow

What happens inside the ML Service for one `PredictFraud` request.

```mermaid
flowchart TD
    A([gRPC PredictFraud<br/>85-dim TransactionFeatures]) --> B[FeaturePipeline:<br/>scale + select]
    B --> C[ModelRegistry:<br/>route to model / ensemble]
    C --> D{model}
    D -->|LightGBM/RF/XGB| E[Tree model predict_proba]
    D -->|GNN| F[GraphSAGE<br/>self-loop edge for single tx]
    D -->|Autoencoder| G[Reconstruction error<br/>inverted scoring]
    D -->|Ensemble| H[Weighted avg<br/>LGB .35 RF .33 XGB .32]
    E --> I[fraud_probability]
    F --> I
    G --> I
    H --> I
    I --> J[SHAP explainer:<br/>per-feature contributions]
    J --> K[FraudPrediction:<br/>prob + is_fraud + SHAP + model_version]
    K --> L([Return to Transaction Service])
    K -.-> M[(audit-channel:<br/>MODEL_PREDICTION hash — optional)]
```

---

### Legend

| Shape | Meaning |
|-------|---------|
| `([ ])` rounded | start / end / terminal state |
| `[ ]` rectangle | process / action |
| `{ }` diamond | decision / branch |
| `[( )]` cylinder | datastore or on-chain ledger write |
| dotted arrow `-.->` | asynchronous / verification / non-blocking link |

> Notes: blockchain writes (audit-channel / alert-channel) are **fire-and-forget and
> non-fatal** — they never block the transaction or alert pipelines. A
> `TRANSACTION_PROCESSED` receipt is anchored for **every** scored transaction, which
> is what makes non-reporting detectable (fabrication-gap closure).
