# Methodology

## 4.Z Why Blockchain and Not a Centralised Database?

### The Core Reviewer Question

A natural challenge to any blockchain-based system is: *"Why not use a PostgreSQL database with an append-only audit log? It would be simpler, faster, and equally tamper-evident within a single institution."* This section addresses that question directly, grounding the answer in the specific trust and compliance requirements of the AML domain and in the concrete architectural decisions of this system.

### The Fundamental Difference: Trust Model

A relational database audit log is only as trustworthy as the institution that controls it. In banking AML compliance, the institution under scrutiny (the bank) is also the entity that controls the audit infrastructure. This creates a structural conflict of interest: the bank could, in principle, suppress transaction records, alter fraud scores, or modify SAR filing timestamps without any external party being able to detect the manipulation. Regulatory audits depend on the bank voluntarily producing accurate records.

The system described in this paper replaces this trust assumption with cryptographic enforcement. The Hyperledger Fabric network comprises three independent organisations — PrimaryBank (Org1), Regulator (Org2), and PartnerBank (Org3) — each operating its own peer node with a full, independent copy of the ledger. Block validation requires a **majority of orderer organisations** to sign every block (`BlockValidation: MAJORITY Writers` in `configtx.yaml`). No single organisation can unilaterally commit, alter, or suppress a record.

### Formal Comparison

| Property | Centralised DB audit log | This system (Hyperledger Fabric) |
|---|---|---|
| **Record immutability** | Admin with `UPDATE`/`DELETE` privilege can silently alter rows; triggers and WAL can be disabled | Every `PutState` call writes to an append-only ledger block; each block's SHA-256 hash is chained to the previous — any alteration invalidates all subsequent hashes, detectable by all peers |
| **Who controls the audit trail** | The bank — the same entity under regulatory scrutiny | Three independent organisations; block signing requires majority consensus across PrimaryBank, Regulator, and PartnerBank |
| **Regulator data access** | Regulator requests records from the bank; bank provides them on trust | Regulator (Org2) operates its own peer node with a full ledger replica — no request required, no trust assumed |
| **Transaction suppression** | Bank can choose not to insert a row for a transaction it wishes to hide | `RecordTransactionProcessed` is called for every ML-scored transaction; absence of a receipt is detectable by the regulator from its own peer |
| **SAR document integrity** | Bank stores SAR PDF on its own file server; file can be silently replaced | SHA-256 of the SAR PDF is anchored on-chain via `RecordSARFiled`; regulator recomputes hash independently to verify the document was not altered after filing |
| **Fraud score auditability** | Fraud probability stored in DB — bank can update it post-hoc | `fraudProbability`, `modelVersion`, and `predictionID` written to audit-channel at ML pipeline time; immutable after block commit |
| **Cross-institution fraud signal** | No standard mechanism; requires bilateral data-sharing agreements | PartnerBank (Org3) is a channel member; alert events are visible to all consortium members in real time via chaincode events (`AUDIT_RECORDED`) |
| **Ordering integrity** | Single DB writer; no consensus required | Three Raft orderer nodes, one per organisation (`orderer0`→Org1, `orderer1`→Org2, `orderer2`→Org3); ordering requires Raft consensus — no single org controls block production |
| **Performance** | Single-node writes: sub-millisecond | Fabric block commit latency: ~400–900ms (measured; see Section 5.X); acceptable for async fraud alert pipeline |

### Specific Implementation Evidence

The comparison above is grounded in concrete implementation decisions:

**1. Fabrication gap closure.** The `RecordTransactionProcessed` chaincode function (`audit-contract/contract.go:174`) writes a tamper-evident processing receipt for every transaction that passes through the ML pipeline, regardless of whether it is flagged as fraud. This closes the fabrication gap: a bank cannot omit a transaction from the audit trail, because the regulator's peer node would detect the absence of a corresponding on-chain receipt. A PostgreSQL audit log cannot provide this guarantee because the bank controls the insert path.

**2. SAR hash anchoring.** The `RecordSARFiled` function (`audit-contract/contract.go:285`) stores the SHA-256 hash of the SAR PDF and the S3 object key on-chain at filing time. The document content never reaches the ledger (protecting SAR confidentiality); only its cryptographic fingerprint does. A regulator can independently verify that the PDF submitted during an investigation matches the hash recorded at filing time — without trusting the bank's file server. A database `VARCHAR` column storing a file path provides no such guarantee.

**3. Multi-org block validation.** The `configtx.yaml` specifies `BlockValidation: MAJORITY Writers` across the three orderer organisations. This means at least two of the three organisations (PrimaryBank, Regulator, PartnerBank) must sign every block. A single compromised or colluding organisation cannot produce a valid block unilaterally. A database has no equivalent multi-party signing mechanism.

**4. Immutable composite key index.** Every audit record creates a composite key index (`audit~entityType~entityID~recordID`) in addition to the primary state entry. This index cannot be deleted without invalidating the block hash. A regulator querying `GetAuditTrail(customerID, "CUSTOMER")` receives every event linked to that customer from its own peer — with cryptographic proof that the list is complete.

### When a Database Would Be Sufficient

Intellectual honesty requires acknowledging the cases where a database audit log would be sufficient:

- A **single-institution** system where the regulator trusts the bank's internal controls and audits only periodically.
- A system where **performance is critical** and sub-millisecond write latency is required (e.g., real-time card authorisation).
- A system where **cross-institutional fraud signal sharing** is not required.

This system is designed for none of those cases. It targets a multi-institution consortium (PrimaryBank + PartnerBank), requires regulator-verified audit trails without institutional trust, and operates on an asynchronous fraud detection pipeline where ~600ms block commit latency is acceptable. Blockchain is not chosen because it is novel — it is chosen because the trust model of the AML compliance domain makes a single-institution database audit trail architecturally insufficient.

## 4.X Feature Domain Adaptation

The Elliptic Bitcoin Transaction Dataset [Weber et al., 2019] provides 166 raw features per transaction: 94 local transaction statistics and 72 aggregated 1-hop neighbourhood statistics. As no comparable publicly labeled bank wire transfer dataset exists — a well-documented constraint in financial crime research — this work employs the Elliptic dataset as a behavioral proxy for supervised model training, following established precedent in the financial crime detection literature.

The feature input to all trained models is a standardized 85-dimensional vector, selected from the 166 Elliptic features by LightGBM feature importance ranking (features 1–68 and 94–110). For production inference on bank wire transfers, a domain adaptation function `_structured_to_elliptic_array()` maps the system's real-time feature extraction output (TransactionFeatures) into this 85-dimensional space. Table X summarizes the mapping.

Of the 85 model input positions, **38 are populated from structured bank transaction data** and **47 are zero-padded**. The 38 mapped features cover all six behavioral indicator categories identified by FATF Recommendation 16:

| FATF Indicator Category | Features Mapped | Example |
|---|---|---|
| Transaction value anomaly | 5 | `amount_usd`, `amount_deviation_score`, `avg_amount_30d` |
| Transaction velocity | 4 | `velocity_1h`, `velocity_24h`, `tx_frequency_1h`, `tx_frequency_24h` |
| Geographic risk | 4 | `geographic_risk_score`, `cross_border_flag`, `country_change_2h`, `distance_km_from_last` |
| Network topology | 6 | `pagerank`, `clustering_coefficient`, `betweenness_centrality`, `direct_fraud_neighbors`, `hops_to_known_fraudster`, community membership |
| Temporal pattern | 5 | `tx_hour`, `day_of_week`, `is_weekend`, `time_since_last_tx_s`, `total_tx_count_30d` |
| Customer/KYC profile | 4 | `kyc_risk_level`, `customer_risk_score`, `days_since_kyc`, `merchant_risk_score` |

The 47 zero-padded positions correspond to Bitcoin-specific structural features (number of input/output addresses, UTXO statistics, script type distributions) that have no semantically equivalent counterpart in bank wire transfer records. These positions contribute zero signal at inference time; the trained model weights for these positions are effectively dormant in production. This is a known and acknowledged limitation: in institutional deployment, models would be retrained on bank-specific transaction data, replacing the Elliptic-derived weights entirely. The current system demonstrates the architecture's capability; the Elliptic dataset provides the only available ground-truth labels at the scale required for ensemble model training.

---

### Feature Mapping Table

Derived from `ml/features/engineering.py:_structured_to_elliptic_array()` and `services/transaction-service/internal/features/extractor.go`.

| Array pos. | Elliptic feature | Bank field (Go/Proto) | Fraud signal captured |
|---|---|---|---|
| 0 | `feature_1` | `amount_usd_equiv` | Transaction value in USD |
| 1 | `feature_2` | `amount_deviation_score` | (current − μ₃₀d) / σ₃₀d |
| 2 | `feature_3` | `velocity_1h` | Cumulative USD sent in 1-hour window |
| 3 | `feature_4` | `velocity_24h` | Cumulative USD sent in 24-hour window |
| 4 | `feature_5` | `tx_frequency_1h` | Transaction count in last 1 hour |
| 5 | `feature_6` | `tx_frequency_24h` | Transaction count in last 24 hours |
| 6 | `feature_7` | `avg_amount_7d` | 7-day rolling mean transaction amount |
| 7 | `feature_8` | `avg_amount_30d` | 30-day rolling mean transaction amount |
| 8 | `feature_9` | `std_amount_30d` | 30-day rolling standard deviation |
| 9 | `feature_10` | `geographic_risk_score` | FATF country risk score (0–100) |
| 10 | `feature_11` | `merchant_risk_score` | Merchant category AML risk score |
| 11 | `feature_12` | `customer_risk_score` | Customer profile risk score |
| 12 | `feature_13` | `pagerank` | PageRank centrality in transaction graph |
| 13 | `feature_14` | `clustering_coefficient` | Local graph clustering coefficient |
| 14 | `feature_15` | `betweenness_centrality` | Betweenness centrality (hub detection) |
| 15 | `feature_16` | `direct_fraud_neighbors` | Count of directly connected flagged entities |
| 16 | `feature_17` | `hops_to_known_fraudster` | Graph distance to nearest known fraudster |
| 17 | `feature_18` | `is_weekend` | Boolean: weekend transaction (structuring risk) |
| 18 | `feature_19` | `cross_border_flag` | Boolean: sender/receiver in different countries |
| 19 | `feature_20` | `country_change_2h` | Boolean: transaction country changed within 2h |
| 20 | `feature_21` | `is_high_risk_merchant` | Boolean: high-risk merchant category |
| 21 | `feature_22` | `kyc_risk_level` | Customer KYC risk tier (integer 0–4) |
| 22 | `feature_23` | `days_since_kyc` | Days elapsed since last KYC verification |
| 23 | `feature_24` | `total_tx_count_30d` | Total transactions in 30-day window |
| 24 | `feature_25` | `tx_hour` | Hour of day (0–23) |
| 25 | `feature_26` | `day_of_week` | Day of week (0=Sunday–6=Saturday) |
| 26 | `feature_27` | `time_since_last_tx_s` | Seconds elapsed since previous transaction |
| 27 | `feature_28` | `distance_km_from_last` | Haversine distance from previous transaction (km) |
| 28–37 | `feature_29–38` | `louvain_community_id` | Community membership (one-hot, 10 buckets) |
| 38–84 | `feature_39–85` | *(zero-padded)* | Unmapped Bitcoin-specific aggregated stats |

---

## Domain Validity of the Elliptic Dataset for Bank Wire Transfer Detection

A natural question is whether Bitcoin transaction features can validly inform bank wire transfer fraud detection. We argue they can, for three reasons. First, financial crime is a behavioral phenomenon: the Elliptic dataset captures the same behavioral patterns — unusual transaction velocity, large-value anomalies, high-risk network centrality, cross-border movement — that FATF and FinCEN identify as universal money laundering typologies regardless of the underlying payment rail. Second, the 38 mapped features are constructed from real-time bank transaction data (not from the Bitcoin dataset itself); the Elliptic training labels supervise learning of behavioral boundaries that are domain-agnostic. Third, the proposed system architecture separates training data from production data: the ML models are pre-trained on Elliptic and deployed; in institutional deployment, the same architecture would be retrained on institution-specific labeled data. The Elliptic dataset thus serves as a functional proof-of-concept in the absence of a publicly available labeled bank transaction benchmark, a limitation shared by all academic work in this area.

---

## 4.Y Data Privacy Architecture: Channel Separation and Application-Layer Hashing

### Design Decision: Channel Separation over Private Data Collections

Hyperledger Fabric offers two mechanisms for data isolation between organizations: channel-based separation and Private Data Collections (PDC). PDC allows a subset of channel members to share private data while only a hash of that data is committed to the shared ledger. This section explains the design decision to use channel-based separation rather than PDC, and documents the application-layer privacy controls that compensate.

### Channel Architecture

The system deploys three logical channels, each serving a distinct compliance function:

| Channel | Purpose | Members |
|---|---|---|
| `kyc-channel` | KYC identity records and verification status | PrimaryBank, Regulator, PartnerBank |
| `alert-channel` | Fraud alerts and investigation status | PrimaryBank, Regulator, PartnerBank |
| `audit-channel` | Immutable processing receipts, SAR hashes, model predictions | PrimaryBank, Regulator, PartnerBank |

All three organizations are members of all three channels by design. This is a deliberate architectural choice, not an oversight.

### Justification for Full Regulatory Visibility

The primary driver is the regulatory mandate. In the AML compliance domain, the Regulator organization (modelling a Financial Intelligence Unit such as FinCEN or the FCA) is legally entitled to full, unimpeded visibility across all transaction records, alert dispositions, and KYC statuses of all member institutions. Restricting the Regulator's ledger access via PDC would conflict with this mandate. Similarly, the PartnerBank organization is included in all channels to enable cross-institutional fraud signal sharing — a core use case for consortium blockchain in banking, established in frameworks such as the SWIFT KYC Registry and the Wolfsberg Group principles.

PDC is architecturally appropriate when a subset of channel members must share raw sensitive data while excluding others. In this system, there is no such subset — every organization has a legitimate compliance interest in every data category. The three-channel design provides logical separation of concerns (KYC lifecycle, fraud alerting, audit trail) rather than access-control-based privacy isolation.

### Application-Layer Privacy Controls

Since all three organizations can read all three channels, customer privacy is enforced at the application layer through two mechanisms:

**1. Identity hashing.** The KYC chaincode stores an `identityHash` (SHA-256 of the customer's identity document), not raw PII. The `RegisterCustomer` call signature is:

```
RegisterCustomer(customerID, identityHash, kycStatus, riskLevel, verifierID)
```

Participating organizations can verify a customer's identity status and risk level without accessing the underlying document data. Raw PII never reaches the ledger.

**2. SAR document off-chain storage.** Suspicious Activity Reports are confidential regulatory filings. The system stores SAR documents in Amazon S3 and anchors only the document's SHA-256 hash on the audit-channel via `RecordSARFiled`. This creates tamper-evident proof of filing — a regulator can verify the document has not been altered by recomputing its hash — without exposing the full SAR content to all channel members on-chain.

### PDC as Future Work

PDC would become necessary if the system were extended to support the following scenario: PrimaryBank wishes to share raw transaction feature vectors (including customer identifiers) with the Regulator for model audit purposes, without exposing those features to PartnerBank. In that case, a `pdc_regulatory_features` collection scoped to `{Org1MSP, Org2MSP}` would be the appropriate mechanism. This is identified as a future enhancement; the current system satisfies the compliance audit requirements of the prototype within its defined organizational trust model.

### Summary

| Privacy concern | Mechanism used | Rationale |
|---|---|---|
| Customer PII | Application-layer SHA-256 hash | PII never reaches the ledger |
| SAR document content | Off-chain S3 + on-chain hash anchor | Tamper-evidence without ledger exposure |
| Cross-org data access | Full regulatory visibility by design | Regulator mandate; cross-institution fraud signal sharing |
| Future feature-level isolation | PDC (not yet implemented) | Identified future work |
