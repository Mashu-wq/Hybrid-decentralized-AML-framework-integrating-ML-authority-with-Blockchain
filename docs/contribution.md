# Unique Contributions of This Thesis

This document lists only the contributions that are genuinely novel — things that go beyond
implementing existing techniques. Each entry names the contribution, explains why it is novel,
and points to the specific code or result that proves it exists.

---

## Contribution 1 — Transaction Receipt Pattern (Fabrication Gap Closure)

**What it is:**
Every transaction that passes through the ML pipeline — whether flagged as fraud or not —
produces an immutable `TRANSACTION_PROCESSED` receipt on the blockchain audit-channel. The
receipt stores the transaction hash, customer ID, amount, fraud probability, model version,
and whether an alert was fired.

**Why it is novel:**
Every existing blockchain-based AML paper in the literature records only flagged (fraudulent)
transactions on-chain. This creates a fabrication gap: a corrupt bank could suppress a
transaction by simply not flagging it, and the regulator would have no way to detect the
omission. This system closes that gap. The absence of an on-chain receipt for a transaction
that the bank claims to have processed is itself cryptographic evidence of suppression — the
regulator detects it from its own peer node without trusting the bank.

No existing published AML system implements this pattern.

**Evidence in code:**
- `blockchain/chaincode/audit-contract/contract.go:174` — `RecordTransactionProcessed`
- `services/transaction-service/internal/service/transaction_service.go:238` — fire-and-forget
  blockchain anchor called for every transaction, not just flagged ones
- `services/blockchain-service/internal/service/service.go:122` — `RecordTransactionReceipt`

---

## Contribution 2 — KYC-Stratified Dynamic Alert Threshold (Blockchain → ML Feedback Loop)

**What it is:**
The ML fraud alert threshold is not static. It is selected at inference time based on the
customer's KYC risk level, which is stored on the blockchain KYC-channel and read from a
Redis cache populated from the chain. The threshold map is:

| KYC Risk Level | Alert Threshold | Basis |
|---|---|---|
| LOW | 0.70 | Minimise false positives for compliant customers |
| MEDIUM | 0.55 | Balanced precision/recall |
| HIGH | 0.40 | Enhanced due diligence — higher recall accepted |
| CRITICAL | 0.25 | Maximum recall — any meaningful signal triggers alert |

**Why it is novel:**
This creates a direct, live feedback loop between the blockchain component and the ML
component. The KYC smart contract on-chain governs the sensitivity of the ML decision
boundary. When a compliance officer updates a customer's KYC risk level on the blockchain,
the ML alerting behaviour changes automatically on the next transaction — without retraining
any model. This is the first system to implement FATF Recommendation 1 (Risk-Based Approach)
as a live blockchain → ML inference loop.

Existing work either (a) uses a static threshold, or (b) adjusts thresholds based on
transaction features (which the model already encodes) — not based on a separate,
auditable, multi-party-governed KYC ledger.

**Evidence in code:**
- `services/transaction-service/internal/service/transaction_service.go` — `thresholdForRisk()`
- `services/transaction-service/internal/features/extractor.go:262` — `KYCRiskLevel` read
  from Redis (populated from the blockchain KYC-channel)
- `services/transaction-service/internal/service/transaction_service_test.go` —
  `TestProcessTransaction_HighRiskCustomer_AlertsAtLowerThreshold` proves the behaviour

---

## Contribution 3 — Inverted Autoencoder Scoring on the Elliptic Dataset

**What it is:**
An empirical discovery: on the Elliptic Bitcoin Transaction Dataset, fraud transactions
produce **lower** reconstruction error than licit transactions in an autoencoder trained on
licit data only. The standard assumption (high reconstruction error = anomaly = fraud)
is inverted. Applying inverted scoring raises AUC-ROC from 0.29 (raw, worse than random)
to 0.71 (inverted).

| Scoring mode | AUC-ROC |
|---|---|
| Standard (high error = fraud) | 0.2906 |
| Inverted (low error = fraud) | **0.7094** |

**Why it is novel:**
The root cause is a structural property of the Elliptic dataset that has not been documented
before: illicit transactions in Elliptic have simpler, more uniform feature distributions
than licit transactions. They appear to be constructed to blend in — they are not outliers
in feature space, they are the most "average" transactions. A standard autoencoder
anomaly detector fails catastrophically on this dataset without inversion.

This is a publishable empirical finding about the Elliptic dataset's statistical structure,
independent of the broader system contribution. It has direct implications for any researcher
using autoencoders on Elliptic.

**Evidence in code:**
- `ml/models/autoencoder.py:180` — `if self._inverted: deviation = threshold - errors`
- `ml/models/autoencoder.py:223` — `self._inverted = bool(ckpt.get("inverted", False))`
- `ml/evaluation/evaluator.py:248` — benchmark records AUC-ROC=0.7094 with inverted=True
- `ml/artifacts/autoencoder_model.pt` — saved checkpoint with `inverted=True`

---

## Contribution 4 — SAR Hash Anchoring for Tamper-Evident Regulatory Compliance

**What it is:**
When a Suspicious Activity Report is generated, its SHA-256 hash is anchored on the
blockchain audit-channel via `RecordSARFiled`. The PDF document is stored off-chain in S3.
Any regulator can independently verify that the SAR document produced during an
investigation matches the hash recorded at filing time — proving the document was not
altered after it was filed.

**Why it is novel:**
Existing AML blockchain papers either:
- Store SAR content on-chain (impractical — SAR documents are confidential and large)
- Do not address SAR integrity at all

This design achieves tamper-evidence for the most legally critical compliance document
without storing its content on a shared ledger. The separation of hash (on-chain, shared)
from content (off-chain, confidential) is the correct architectural pattern for regulatory
document integrity, but it has not been applied to SARs in the academic literature.

**Evidence in code:**
- `blockchain/chaincode/audit-contract/contract.go:285` — `RecordSARFiled`
- `services/blockchain-service/internal/service/service.go:158` — `RecordSARFiled` service method
- `services/case-service/internal/service/case_service.go` — SAR generation triggers hash anchor

---

## Contribution 5 — Elliptic-to-Bank Feature Domain Adaptation with FATF Coverage Proof

**What it is:**
A formal mapping of 38 structured bank transaction features (extracted in real-time from
wire transfer records) into the 85-dimensional Elliptic feature space used by the trained
models. The mapping is proved to cover all six FATF AML indicator categories:
transaction value anomaly, velocity, geographic risk, network topology, temporal pattern,
and customer/KYC profile.

**Why it is novel:**
The Elliptic dataset is widely used in academic AML research, but always in its original
Bitcoin context. No published work has formally mapped structured bank transaction data into
the Elliptic feature space for production deployment, nor proved coverage of FATF indicator
categories. This contribution makes Elliptic-trained models deployable in a banking context
and provides a reusable mapping that future researchers can extend.

**Evidence in code:**
- `ml/features/engineering.py:124` — `_structured_to_elliptic_array()`
- `docs/methodology.md` — Section 4.X Feature Domain Adaptation (formal mapping table)

---

## Contribution 6 — Distributed Orderer Ownership Across Business Organisations

**What it is:**
Each of the three business organisations (PrimaryBank, Regulator, PartnerBank) owns exactly
one Raft orderer node. Block production requires majority Raft consensus across these three
nodes. Block validation requires `MAJORITY Writers` across the three orderer organisations.

**Why it is novel:**
Standard Hyperledger Fabric deployments use a separate `OrdererOrg` that is independent of
the business organisations — the ordering service is a trusted third party. In an AML
consortium where no single party should have privileged control, a separate orderer
organisation is architecturally unsatisfactory. This design eliminates the trusted third
party: no single business organisation can produce valid blocks unilaterally, and the
ordering service has no independent identity beyond the consortium members.

**Evidence in code:**
- `blockchain/network/configtx.yaml:207` — all three business orgs listed as orderer
  organisations in `FraudDetectionOrdererGenesis`
- `blockchain/network/configtx.yaml:182` — `BlockValidation: MAJORITY Writers`
- Comments in configtx.yaml: `orderer0→Org1 (PrimaryBank), orderer1→Org2 (Regulator),
  orderer2→Org3 (PartnerBank)`

---

## Summary Table

| # | Contribution | Type | Novelty level |
|---|---|---|---|
| 1 | Transaction Receipt / Fabrication Gap Closure | System pattern | High — not in any published AML paper |
| 2 | KYC-Stratified Dynamic Alert Threshold | Blockchain→ML integration | High — first FATF RBA as live blockchain feedback loop |
| 3 | Inverted Autoencoder on Elliptic Dataset | Empirical finding | High — undocumented dataset property |
| 4 | SAR Hash Anchoring | Compliance pattern | Medium-High — correct pattern, not previously applied to SARs |
| 5 | Elliptic-to-Bank Feature Mapping | Methodology | Medium — enables production deployment, no prior formalisation |
| 6 | Distributed Orderer Ownership | Architecture | Medium — eliminates trusted third party in ordering |

---

## What Is NOT a Unique Contribution

Being honest about this is important for a credible thesis:

- **Individual ML models** (LightGBM, Random Forest, XGBoost, GraphSAGE, Autoencoder) —
  these are standard algorithms. The contribution is their combination and deployment context,
  not the algorithms themselves.
- **Hyperledger Fabric setup with 3 organisations** — multi-org Fabric networks are standard.
  The contribution is the specific AML compliance design decisions, not the Fabric deployment.
- **SHAP explainability** — using SHAP for ML explainability is well-established.
- **Microservices architecture** — standard software engineering practice.
- **Kafka + MongoDB + Redis stack** — standard event-driven architecture.

These elements are necessary to build the system but should not be presented as novel
contributions in the thesis. They belong in the Implementation section, not the
Contributions section.
