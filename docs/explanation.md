# Blockchain & ML — Detailed Explanation

> A narrative, in-depth walkthrough of the two core technical contributions of this
> thesis: the **Hyperledger Fabric blockchain layer** and the **machine-learning
> fraud-intelligence layer**. Where `archi.md` gives diagrams and reference tables,
> this document explains *how* each part works and *why* it is designed that way.

---

# PART I — The Blockchain Portion

## 1. Why a blockchain at all?

A fraud/AML system already has databases. The thesis question is: *what does a
blockchain add that a database cannot?* The answer is **tamper-evidence under
distrust**.

In a normal bank, the bank owns its database. If a regulator asks "did you screen
this transaction?", the bank produces a log — but the bank also *controls* that log.
A malicious or negligent bank could:

- **delete** a record of a suspicious transaction it failed to report, or
- **fabricate** a record claiming it screened something it never did, or
- **alter** a Suspicious Activity Report (SAR) after the fact.

A regular database cannot prove this didn't happen, because the same party that
stores the data can rewrite it. The blockchain solves this by making the audit trail:

1. **Append-only and hash-chained** — every block references the previous block's
   hash, so altering an old record breaks every block after it.
2. **Replicated across mutually-distrusting organizations** — the bank, a partner
   bank, and the **regulator** each hold an identical copy. No single party can
   change history unilaterally.
3. **Multi-signed** — a block is only valid if a **majority** of organizations sign
   it, so the bank cannot write to "its own" ledger alone.

That combination is what a database fundamentally cannot provide, and it is the
backbone of the project's central contribution (see §9, *Fabrication-Gap Closure*).

## 2. Why Hyperledger Fabric (and not a public chain)?

A public blockchain (Bitcoin/Ethereum) is the wrong tool here:

- **Privacy:** customer PII and transaction details must never be world-readable.
- **Permissioning:** only known, vetted institutions (banks + regulator) participate.
- **Throughput & cost:** AML needs predictable latency and no gas fees.
- **Identity:** every action must be tied to a known organization (MSP), not an
  anonymous wallet.

**Hyperledger Fabric** is a *permissioned* blockchain that gives exactly this:
membership is controlled by **MSPs (Membership Service Providers)**, data can be
partitioned into **channels**, and smart contracts (**chaincode**) run business
logic with organizational endorsement policies.

## 3. Network design

```
Org1MSP (PrimaryBank)   Org2MSP (Regulator)   Org3MSP (PartnerBank)
  peer0.org1              peer0.org2             peer0.org3
  orderer0               orderer1               orderer2
  CouchDB                CouchDB                CouchDB
            \                |                 /
             \---  Raft ordering service  ---/
                  (MAJORITY block validation)
```

- **3 organizations**, each a distinct trust domain. Crucially, **Org2 is the
  regulator** — an independent party that holds the full ledger but is not the bank.
- **3 Raft orderers**, one per org. Raft provides crash-fault-tolerant ordering of
  transactions into blocks. Because the orderers belong to different orgs, no single
  org controls block production.
- **Block validation policy = MAJORITY** — at least 2 of the 3 orgs must endorse and
  sign. This is what stops the bank from writing alone.
- **CouchDB** is the state database on each peer (instead of LevelDB). CouchDB stores
  state as JSON and supports **rich queries**, which the chaincode uses for indexed
  lookups like "all alerts at risk level HIGH".
- Measured block-commit latency is **~400–900 ms**, perfectly acceptable because all
  on-chain writes are **asynchronous / fire-and-forget** (see §6).

## 4. Three channels — and why they are separated

A *channel* in Fabric is an isolated ledger with its own chaincode. The system uses
three, each modeling a different domain with different access and lifecycle needs:

| Channel | Holds | Why separate |
|---------|-------|--------------|
| `kyc-channel` | Customer identity hashes, KYC status, risk level | Identity lifecycle is slow-changing and legally sensitive; isolating it keeps KYC reads/writes from competing with high-volume traffic. |
| `alert-channel` | Fraud alert records + investigation status | Alerts are operational fraud signals shared across institutions (a fraudster flagged at one bank is a signal for the partner bank). |
| `audit-channel` | Processing receipts, SAR hashes, investigator actions, model predictions | This is the **regulator's evidence ledger** — the immutable record of *everything the pipeline did*. It is the highest-integrity, append-only trail. |

All three orgs are members of all three channels (the regulator must see everything,
and cross-institution fraud signal is a design goal).

## 5. The three chaincodes (smart contracts)

Each channel runs one chaincode. They are written in Go and live in
`blockchain/chaincode/`.

### 5.1 `kyc-contract` (kyc-channel)
Manages the identity lifecycle:
- `RegisterCustomer` — stores `SHA-256(document)` (never raw PII), status `PENDING`.
- `UpdateKYCStatus` — moves a customer to `APPROVED`/`REJECTED` with a risk level
  (LOW/MEDIUM/HIGH/CRITICAL). This is the moment the customer's risk tier becomes a
  tamper-evident on-chain fact.
- `GetKYCRecord` / `GetKYCHistory` / `GetRiskLevel` — reads, including full history of
  state changes (Fabric keeps every version of a key).

### 5.2 `alert-contract` (alert-channel) — **upgraded to v1.1**
Records fraud alerts as immutable objects:
- `CreateAlert(alertID, customerID, txHash, fraudProb, riskScore, modelVersion)` —
  writes an `AlertRecord` and **derives the risk level on-chain**.
- `UpdateAlertStatus`, `GetAlert`, `GetAlertsByCustomer`, `GetAlertsByRiskLevel`,
  `GetAlertStats` — operational reads/writes, backed by CouchDB composite-key indexes
  (`alert~customer`, `alert~risk`, `alert~status`).

The v1.1 change (see §11) is central to making the alert levels meaningful.

### 5.3 `audit-contract` (audit-channel)
The evidence ledger. Every record is a hashed `AuditRecord` keyed by
`(entityType, entityID)`:
- `RecordTransactionProcessed` — a receipt for **every** ML-scored transaction.
- `RecordModelPrediction` — the model output + SHAP explanation hash.
- `RecordSARFiled` — anchors `SHA-256(SAR PDF)` (the document itself stays in S3).
- `RecordInvestigatorAction` — e.g. `EVIDENCE_REVIEWED`, `CASE_CREATED`.
- `GetAuditTrail(entityID, entityType)` and `GetComplianceReport(start, end)` — the
  regulator's query surface.

## 6. How the application talks to the chain

The Go microservices do **not** speak Fabric directly. A single **Blockchain
Service** (`:9005`) wraps the **Fabric Gateway SDK** and exposes a plain internal
HTTP API (`/internal/v1/...`). It connects using the **Org1 connection profile** and
the Gateway SDK automatically discovers the endorsing peers needed to satisfy the
chaincode's majority endorsement policy.

This indirection matters:
- Services stay simple — they POST JSON, not manage crypto material and TLS to peers.
- All blockchain access is centralized, observable, and swappable.

**Anchoring is fire-and-forget and non-fatal.** When the Transaction Service finishes
scoring a transaction, it calls `AnchorTransactionReceipt()` in a goroutine and does
**not** wait for or fail on the result. Likewise the Alert Service anchors alerts in
the background and back-fills the returned Fabric `txId` onto the alert row. This
guarantees the ~400–900 ms blockchain latency never slows or breaks the real-time
fraud pipeline — the ledger is an *evidence* layer, not a *blocking* dependency.

## 7. What gets written, and when

```
KYC approve            → kyc-contract.UpdateKYCStatus      (kyc-channel)
Every scored tx        → audit-contract.RecordTransactionProcessed (audit-channel)
Alert fires            → alert-contract.CreateAlert         (alert-channel)
Investigator action    → audit-contract.RecordInvestigatorAction (audit-channel)
SAR generated          → audit-contract.RecordSARFiled (hash only) (audit-channel)
```

The most important of these is **`RecordTransactionProcessed` for every transaction**
— not just flagged ones. That is the heart of the contribution below.

## 8. Privacy model

Blockchains are replicated, so putting sensitive data on-chain would be a privacy
disaster. The design keeps PII **off** the ledger entirely:

- **Identity** → only `SHA-256(document)` is stored. The hash proves "this exact
  document existed" without revealing it.
- **SAR documents** → the PDF lives in S3; only `SHA-256(PDF)` is anchored. Anyone can
  later re-hash the PDF and compare to prove it wasn't altered, but the report content
  is never exposed on-chain.
- **Transactions** → the receipt stores `txHash`, amount, country, model version, and
  the fraud decision — operational metadata, not full customer detail.

(*Future work:* Private Data Collections (PDC) for feature-level, regulator-only
visibility.)

## 9. The core contribution — "Fabrication-Gap Closure"

This is the thesis's central idea, and it is worth stating precisely.

Most "blockchain for AML" systems only put **flagged** transactions or **filed SARs**
on-chain. That leaves a gap: a bank can simply **never flag** a suspicious
transaction, and there is no on-chain evidence that the transaction was ever seen.
The absence of a flag is indistinguishable from "nothing suspicious happened."

This system closes that gap by anchoring a `TRANSACTION_PROCESSED` receipt for
**every** transaction the ML pipeline scores — flagged or not. Because the
**regulator (Org2) independently holds the full audit-channel ledger**:

- If the bank processed a transaction, there is a receipt the regulator can see.
- If a transaction is *missing* a receipt, that absence is itself detectable evidence
  of suppression — without the regulator having to trust or query the bank.

In other words, the system makes **non-reporting observable**. That is something a
private database can never do, because the bank controls its own database.

## 10. Audit queries and the compliance report

Audit records are indexed on-chain by a **composite key `(entityType, entityID)`**,
not by customer. So queries are:

- `GetAuditTrail(entity_id=<tx_hash>, entity_type=TRANSACTION)` → the processing receipt.
- `GetAuditTrail(entity_id=<case_id>, entity_type=CASE)` → SAR_FILED + investigator actions.

The **compliance report** (`GetComplianceReport(start, end)`) aggregates everything in
a date range — total events, transactions processed, SARs filed, investigator
actions, and a breakdown by entity type. This is the "regulator view": the regulator
pulls it **from their own peer node**, not from the bank. No trust required.

## 11. Alert risk-level derivation (the v1.1 upgrade)

Originally `alert-contract.deriveRiskLevel` keyed the alert's risk level on the raw
**ML fraud probability**:

```
fraudProb > 0.85 → CRITICAL ; >= 0.70 → HIGH ; >= 0.50 → MEDIUM ; else LOW
```

On the adapted bank-wire feature space the model emits a *narrow* probability band
(~0.006–0.009 for nearly every transaction — see Part II §9), so **every** alert fell
into `LOW`. The level carried no information.

**v1.1** changes the derivation to key on the upstream **composite risk score** (a
0–100 hybrid of the ML signal and rule-based factors, computed by the Transaction
Service — Part II §8):

```
riskScore > 85 → CRITICAL ; >= 70 → HIGH ; >= 50 → MEDIUM ; else LOW
```

Now the on-chain alert level reflects genuine transaction risk (KYC tier + merchant +
geography + behavior), producing a real LOW/MEDIUM/HIGH/CRITICAL spread.

## 12. Chaincode lifecycle (how the v1.1 upgrade was deployed)

Fabric chaincode follows a *lifecycle*: **package → install (per org) → approve (per
org) → commit (channel)**. Upgrading is the same flow with a higher **sequence**
number. The v1.1 deployment:

1. Packaged `alert-contract` and **installed** it on each peer (the peer compiles the
   Go code into a build image — this is the slow step).
2. Each org **approved** version 1.1 / sequence 2.
3. Committed once a **majority** (Org1 + Org3) approved; later caught Org2 up so all
   three endorse.

A practical gotcha: the first-time Go build inside a peer can exceed the default 30 s
chaincode launch timeout, causing transient install failures. The fix applied was to
raise `CORE_CHAINCODE_EXECUTETIMEOUT` to 300 s on the peers (takes effect on the next
fresh network bring-up).

---

# PART II — The Machine-Learning Portion

## 1. The problem

Detect illicit (money-laundering / fraud) transactions in a stream, where:
- the **vast majority of transactions are legitimate** (extreme class imbalance), and
- a missed illicit transaction (false negative) is far more costly than a false alarm,
  but too many false alarms make the system unusable.

So the goal is **high recall on fraud without drowning analysts in false positives** —
the classic AML precision/recall trade-off, handled here with a risk-based approach.

## 2. The dataset

The models are trained on the **Elliptic Bitcoin Transaction Dataset**:
- 203,769 transactions; **46,564 labeled** (4,545 illicit, 42,019 licit).
- **166 anonymized features** per transaction node, plus temporal graph edges.

Two deliberate methodology choices:
- **Temporal 80/20 split** (by time step, *not* random). Fraud evolves over time;
  randomly shuffling would let the model "peek" at future patterns — data leakage.
  Splitting by time simulates real deployment (train on past, predict the future).
- **SMOTE on the training split only.** Synthetic Minority Over-sampling balances the
  classes so the model actually learns the rare fraud signal — but it is applied
  *only to training*, never to the test set, so evaluation stays honest.

## 3. Feature engineering & domain adaptation

This is the most subtle part, and a genuine research contribution.

The models are trained on **Bitcoin** features, but production sees **bank wire
transfers**. These are different worlds. The pipeline bridges them:

1. **Selection:** the raw 166 Elliptic features are reduced to the **top 85** by
   LightGBM importance (indices 1–68 and 94–110). All models and the gRPC contract use
   this fixed 85-dimensional vector.
2. **Domain adaptation:** `_structured_to_elliptic_array()` maps real bank-wire fields
   (amount, velocity, geography, counterparty, KYC profile, …) into **38** of the 85
   positions. The remaining **47** are **zero-padded** — they are Bitcoin-specific
   graph statistics with no bank-wire equivalent.
3. **FATF grounding:** the mapped features cover the **6 FATF Recommendation-16
   behavioral categories**: value anomaly, velocity, geographic risk, network
   topology, temporal pattern, and customer/KYC profile.

> **Honest consequence:** because 47/85 inputs are zero for bank wires, the model has
> less signal than it did on Bitcoin, which is one reason its probability output is a
> narrow band in production (see §9). This is openly acknowledged and is precisely why
> the hybrid composite score (§8) exists.

## 4. The live feature extractor

Before the model ever runs, the **Transaction Service** enriches each raw transaction
into a feature vector, using **Redis** for stateful, real-time signals:

- **Temporal:** hour of day, day of week, time since last transaction.
- **Velocity:** transaction frequency in 1h / 24h windows (Redis sorted sets).
- **Amount behavior:** rolling 7d/30d averages, standard deviation, and an
  **amount-deviation z-score** (how anomalous this amount is for *this* customer).
- **Geographic:** a `GeographicRiskScore` per country (e.g. KP 100, IR 95, RU 72,
  KY 50, US 10) and a cross-border flag.
- **Merchant:** a `MerchantRiskScore` per category (gambling 90, crypto 75,
  money-transfer 68, default 15) and a high-risk-merchant flag.
- **KYC profile:** the customer's `CustomerRiskScore` and risk tier, read from Redis,
  which is itself fed from the **blockchain KYC channel** via the `kyc.events` topic.

This is what makes scoring **stateful** — the same $2,000 transaction looks very
different for a customer with no history versus one whose average is $2,000.

## 5. The six models

| Model | What it is good at |
|-------|--------------------|
| **LightGBM** | Best overall balance; fast gradient-boosted trees; handles imbalance natively (`is_unbalance`). |
| **Random Forest** | Highest precision (88%) — few false positives, but lower recall. |
| **XGBoost** | Strong all-rounder; `scale_pos_weight` tuned for the 1:9 imbalance. |
| **GNN (GraphSAGE)** | Designed to exploit the transaction *graph*; high recall but noisy precision. |
| **Autoencoder** | Unsupervised anomaly detector; used as a novelty signal, not a primary classifier. |
| **Ensemble** | Weighted average (LGB 0.35, RF 0.33, XGB 0.32) — combines the tree models. |

**Measured results (Elliptic, temporal split, SMOTE):**

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC |
|-------|-----------|--------|----|---------|--------|
| LightGBM | 64.6% | 68.2% | 66.4% | 96.5% | 69.7% |
| Random Forest | 88.3% | 56.9% | 69.2% | 96.4% | 68.2% |
| XGBoost | 70.6% | 63.2% | 66.7% | 96.0% | 69.1% |
| GNN | 22.3% | 66.5% | 33.4% | 88.9% | 54.7% |
| Autoencoder | 6.6% | 68.2% | 12.1% | 70.9% | 38.9% |

Two model-specific quirks worth understanding:

- **Autoencoder uses *inverted* scoring.** Normally an autoencoder flags anomalies as
  *high* reconstruction error. On Elliptic, illicit transactions have *simpler, more
  uniform* features and therefore *lower* reconstruction error than licit ones. So the
  scoring is inverted (`inverted=True`) — fraud is the low-error tail.
- **GNN degrades gracefully in production.** A graph network needs neighbors to pass
  messages. For single-transaction real-time inference there is no subgraph yet, so
  `predict_proba()` uses a self-loop edge index (effectively a feature-only MLP). Full
  graph inference needs a pre-built subgraph from the PostgreSQL edge table — that is
  noted future work.

## 6. Why an ensemble?

The models have complementary error profiles: Random Forest is precise but misses
fraud (low recall); LightGBM/XGBoost catch more but with more false positives. A
weighted ensemble blends them so the combined decision is steadier than any single
model. Weights are derived from individual ROC-AUC (no joint calibration yet — also
acknowledged future work).

## 7. Serving and the inference path

The **ML Service** (Python) loads all six models into memory at startup (~60–90 s) and
exposes two interfaces:

- **gRPC `PredictFraud`** (`:50051`) — the production path. The Transaction Service
  sends the 85-dim `TransactionFeatures` proto and gets back a `FraudPrediction`
  (probability, is_fraud, model version, SHAP contributions).
- **FastAPI REST** (`:8000`, Swagger at `/docs`) — `/predict`, `/explain`, `/compare`
  for interactive use and model comparison.

A `ModelRegistry` loads and serves the trained `.pkl`/`.pt` artifacts; if the ML
service is unreachable, the Transaction Service falls back to a heuristic so the
pipeline never hard-fails.

## 8. The hybrid composite risk score (the key recent addition)

**The problem it solves.** As explained in §3 and §9, the ML probability on bank wires
is a narrow band (~0.008 for almost everything). If alerting and risk levels relied on
that number alone, every alert would look identical. ML alone is not enough on this
adapted data.

**The solution.** Real AML systems never rely on a single ML score — they blend it
with **rule-based risk factors** (the FATF "risk-based approach"). The Transaction
Service computes a **composite 0–100 risk score**:

```
compositeRiskScore =  0.10 · (fraud_probability · 100)     ← ML signal (weighted lightly)
                   +  0.30 · CustomerRiskScore             ← KYC tier (LOW20/MED50/HIGH80/CRIT95)
                   +  0.30 · MerchantRiskScore             ← category (gambling90 … default15)
                   +  0.30 · GeographicRiskScore           ← jurisdiction (IR95 … US10)
                   +  bonuses:  cross-border        +12
                                amount anomaly  up to +12
                                high-risk merchant  +6
                   →  clamped to [0, 100]
```

The ML probability is kept (it still contributes and is preserved on-chain as the true
model output) but weighted lightly, because on this data the *rule-based* factors carry
the differentiating signal. This composite then drives:
- **whether/how strongly to alert**, and
- the **on-chain risk level** via the v1.1 chaincode (Part I §11).

**Why this is defensible, not a hack:** blending ML scores with rule-based typologies
(geography, merchant category, customer risk tier, structuring/velocity) is exactly how
production transaction-monitoring systems work. It also makes the system *explainable*
— an analyst can see *why* a score is high (e.g. "crypto + Iran + cross-border"),
which a raw 0.008 probability never reveals.

**It is dynamic and stateful — proven.** Two transactions identical except for country,
for one CRITICAL customer:

| Transaction | Geo term | AvgAmount30D | Amount anomaly | composite | level |
|-------------|----------|--------------|----------------|-----------|-------|
| crypto / **US** (1st) | 10 | 0 (no history) | +12 (looks anomalous) | **72.08** | HIGH |
| crypto / **IR** (2nd) | 95 | 2000 (history now) | +0 (now normal) | **85.58** | CRITICAL |

Changing only the country moved the geography term; and the *amount-anomaly* term moved
on its own because the first transaction established a history baseline in Redis. A
mock/hardcoded system cannot reproduce this — the score genuinely depends on live state.

## 9. Explainability

Every prediction is explainable, which is a regulatory requirement for AML:

- **SHAP** — `TreeExplainer` for the tree models (exact, fast), `KernelExplainer`
  fallback for GNN/Autoencoder. Produces per-feature contributions ("amount pushed
  this toward fraud by +X").
- **LIME** — fits a local linear surrogate per prediction for an independent view.
- **Counterfactuals** — "what minimal change would have flipped this decision?"

SHAP values are serialized to JSON, stored alongside the alert in PostgreSQL, **and**
hashed into the `audit-channel` `MODEL_PREDICTION` record — so the explanation behind
every decision is itself tamper-evident.

## 10. Honest limitations (and how they're handled)

| Limitation | Mitigation / status |
|------------|---------------------|
| 47/85 features zero-padded for bank wires → narrow ML probability band | Hybrid composite score (§8) supplies the differentiating signal |
| GNN can't do true graph inference on single transactions | Degrades to feature-only MLP; full subgraph inference is future work |
| Autoencoder weak on Elliptic (AUC 70.9%) | Used as a novelty/secondary signal, not a primary classifier (inverted scoring) |
| Ensemble weights from ROC-AUC, no joint calibration | Acknowledged future work |
| Alert *firing* still gates on raw ML prob vs KYC-tier threshold | Works today (HIGH/CRITICAL thresholds tuned to the model's band); gating firing on the composite score is the natural next step |

---

# How the two layers reinforce each other

The blockchain and ML layers are not independent — they form one tamper-evident
intelligence loop:

1. ML scores a transaction and produces a **composite risk score + SHAP explanation**.
2. The blockchain anchors a **receipt for every score** (audit-channel), an **alert
   with its derived risk level** (alert-channel), and the **explanation hash**.
3. The regulator, holding an independent copy, can verify *what the model decided, on
   every transaction, and that nothing was hidden or altered* — turning an opaque,
   trust-me ML pipeline into a **verifiable, regulator-auditable** one.

That fusion — explainable ML decisions made tamper-evident and independently
auditable on a permissioned blockchain — is the project's overall contribution.
