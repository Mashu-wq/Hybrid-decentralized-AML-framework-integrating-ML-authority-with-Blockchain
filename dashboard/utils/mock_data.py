"""
Realistic mock data for dashboard demo when backend services are offline.
All data reflects the actual domain model structures from the Go/Python services.
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta
import uuid

_rng = random.Random(42)

RISK_LEVELS   = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COUNTRIES     = ["US", "GB", "DE", "SG", "CN", "NG", "BR", "AE", "RU", "JP"]
KYC_STATUSES  = ["PENDING", "APPROVED", "REJECTED", "UNDER_REVIEW", "EXPIRED"]
ALERT_STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "ESCALATED"]
CASE_STATUSES  = ["OPEN", "IN_REVIEW", "PENDING_SAR", "CLOSED", "ESCALATED"]

def _ts(days_ago: float = 0, hours_ago: float = 0) -> str:
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat() + "Z"

def _uid() -> str:
    return str(uuid.UUID(int=_rng.getrandbits(128)))

# ── KYC Customers ────────────────────────────────────────────────────────────

_NAMES = [
    "Amara Osei", "Lena Müller", "Raj Patel", "Sofia Chen", "Marcus Johnson",
    "Fatima Al-Hassan", "Ivan Petrov", "Yuki Tanaka", "Claire Dubois", "Omar Sheikh",
    "Priya Sharma", "Wei Zhang", "Elena Rossi", "Ahmed Nasser", "Ana Rodrigues",
    "John Kim", "Mary O'Brien", "Kwame Asante", "Natasha Volkova", "Carlos Reyes",
]

def mock_customers(n: int = 20) -> list[dict]:
    statuses = ["APPROVED"] * 10 + ["PENDING"] * 5 + ["UNDER_REVIEW"] * 3 + ["REJECTED"] * 2
    rows = []
    for i in range(n):
        risk = _rng.choice(RISK_LEVELS)
        rows.append({
            "id":              _uid(),
            "full_name":       _NAMES[i % len(_NAMES)],
            "email":           f"user{i+1}@example.com",
            "country_code":    _rng.choice(COUNTRIES),
            "kyc_status":      statuses[i % len(statuses)],
            "risk_level":      risk,
            "identity_hash":   f"sha256:{uuid.UUID(int=_rng.getrandbits(128)).hex}",
            "blockchain_tx_id": _uid(),
            "created_at":      _ts(days_ago=_rng.uniform(1, 180)),
            "updated_at":      _ts(days_ago=_rng.uniform(0, 30)),
            "source_of_funds": _rng.choice(["Employment", "Business", "Investment", "Inheritance"]),
            "occupation":      _rng.choice(["Engineer", "Trader", "Business Owner", "Director"]),
            "expected_monthly_volume": round(_rng.uniform(1000, 500000), 2),
        })
    return rows

# ── Fraud Alerts ─────────────────────────────────────────────────────────────

def mock_alerts(n: int = 30) -> list[dict]:
    priorities = {
        "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1
    }
    rows = []
    for i in range(n):
        prob = _rng.uniform(0.35, 0.99)
        if prob > 0.85:
            priority, risk = 4, "CRITICAL"
        elif prob >= 0.70:
            priority, risk = 3, "HIGH"
        elif prob >= 0.50:
            priority, risk = 2, "MEDIUM"
        else:
            priority, risk = 1, "LOW"

        status = _rng.choices(
            ALERT_STATUSES,
            weights=[30, 20, 30, 15, 5]
        )[0]
        rows.append({
            "alert_id":           _uid(),
            "customer_id":        _uid(),
            "tx_hash":            f"0x{uuid.UUID(int=_rng.getrandbits(128)).hex[:40]}",
            "fraud_probability":  round(prob, 4),
            "risk_score":         round(prob * 100, 1),
            "priority":           priority,
            "risk_level":         risk,
            "status":             status,
            "model_version":      "ensemble-v1.2",
            "assignee_id":        _uid() if status != "OPEN" else "",
            "blockchain_tx_id":   _uid(),
            "created_at":         _ts(hours_ago=_rng.uniform(0.5, 72)),
            "updated_at":         _ts(hours_ago=_rng.uniform(0, 24)),
            "resolution_notes":   "Confirmed fraud pattern via SHAP analysis." if status == "RESOLVED" else "",
        })
    return rows

def mock_alert_stats() -> dict:
    return {
        "TotalAlerts":         142,
        "OpenAlerts":          38,
        "CriticalAlerts":      12,
        "HighAlerts":          26,
        "MediumAlerts":        54,
        "LowAlerts":           50,
        "ResolvedAlerts":      72,
        "FalsePositives":      18,
        "EscalatedAlerts":     14,
        "AvgFraudProbability": 0.683,
        "FalsePositiveRate":   0.127,
        "AvgResolutionTimeMin": 94.3,
        "EscalationRate":      0.098,
        "Period":              "24h",
    }

# ── Cases ─────────────────────────────────────────────────────────────────────

def mock_cases(n: int = 20) -> list[dict]:
    rows = []
    for i in range(n):
        prob = _rng.uniform(0.4, 0.99)
        status = _rng.choices(CASE_STATUSES, weights=[30, 25, 15, 25, 5])[0]
        rows.append({
            "case_id":            _uid(),
            "alert_id":           _uid(),
            "customer_id":        _uid(),
            "tx_hash":            f"0x{uuid.UUID(int=_rng.getrandbits(128)).hex[:40]}",
            "title":              f"Suspicious Transaction Pattern #{1000+i}",
            "description":        "Multiple high-value transfers detected across high-risk jurisdictions.",
            "status":             status,
            "priority":           4 if prob > 0.85 else 3 if prob >= 0.70 else 2,
            "fraud_probability":  round(prob, 4),
            "risk_score":         round(prob * 100, 1),
            "sar_required":       prob > 0.80,
            "sar_s3_key":         f"s3://aml-sars/{_uid()}.pdf" if status == "PENDING_SAR" else "",
            "assignee_id":        _uid(),
            "blockchain_tx_id":   _uid(),
            "created_at":         _ts(days_ago=_rng.uniform(0, 30)),
            "updated_at":         _ts(hours_ago=_rng.uniform(0, 48)),
            "resolution_summary": "Referred to law enforcement." if status == "CLOSED" else "",
        })
    return rows

def mock_case_stats() -> dict:
    return {
        "TotalCases":        87,
        "OpenCases":         23,
        "InReviewCases":     18,
        "PendingSARCases":   11,
        "ClosedCases":       31,
        "CriticalCases":     8,
        "SARGenerated":      14,
        "AvgResolutionHours": 36.7,
        "Period":            "7d",
    }

# ── ML Model Benchmarks ───────────────────────────────────────────────────────

def mock_model_comparison() -> dict:
    return {
        "active_model": "ensemble",
        "models": [
            {
                "model_name":      "lightgbm",
                "model_version":   "1.2.0",
                "precision":       0.6461,
                "recall":          0.6818,
                "f1_score":        0.6635,
                "accuracy":        0.9712,
                "auc_roc":         0.9649,
                "auc_pr":          0.6970,
                "true_positives":  310,
                "false_positives": 170,
                "true_negatives":  8243,
                "false_negatives": 145,
                "sample_count":    8868,
                "avg_latency_ms":  3.2,
                "p95_latency_ms":  8.1,
                "period":          "test",
            },
            {
                "model_name":      "random_forest",
                "model_version":   "1.2.0",
                "precision":       0.8834,
                "recall":          0.5692,
                "f1_score":        0.6923,
                "accuracy":        0.9801,
                "auc_roc":         0.9638,
                "auc_pr":          0.6820,
                "true_positives":  259,
                "false_positives": 34,
                "true_negatives":  8379,
                "false_negatives": 196,
                "sample_count":    8868,
                "avg_latency_ms":  15.7,
                "p95_latency_ms":  32.4,
                "period":          "test",
            },
            {
                "model_name":      "xgboost",
                "model_version":   "1.2.0",
                "precision":       0.7064,
                "recall":          0.6324,
                "f1_score":        0.6674,
                "accuracy":        0.9731,
                "auc_roc":         0.9597,
                "auc_pr":          0.6910,
                "true_positives":  288,
                "false_positives": 120,
                "true_negatives":  8293,
                "false_negatives": 167,
                "sample_count":    8868,
                "avg_latency_ms":  4.8,
                "p95_latency_ms":  11.2,
                "period":          "test",
            },
            {
                "model_name":      "gnn",
                "model_version":   "1.2.0",
                "precision":       0.2234,
                "recall":          0.6645,
                "f1_score":        0.3344,
                "accuracy":        0.8932,
                "auc_roc":         0.8886,
                "auc_pr":          0.5470,
                "true_positives":  302,
                "false_positives": 1051,
                "true_negatives":  7362,
                "false_negatives": 153,
                "sample_count":    8868,
                "avg_latency_ms":  28.4,
                "p95_latency_ms":  62.1,
                "period":          "test",
            },
            {
                "model_name":      "autoencoder",
                "model_version":   "1.2.0",
                "precision":       0.0661,
                "recall":          0.6815,
                "f1_score":        0.1205,
                "accuracy":        0.7218,
                "auc_roc":         0.7094,
                "auc_pr":          0.3890,
                "true_positives":  310,
                "false_positives": 4380,
                "true_negatives":  4033,
                "false_negatives": 145,
                "sample_count":    8868,
                "avg_latency_ms":  7.3,
                "p95_latency_ms":  18.6,
                "period":          "test",
            },
        ],
    }

# ── Blockchain Audit ──────────────────────────────────────────────────────────

def mock_audit_trail(entity_id: str) -> dict:
    event_types = [
        "TRANSACTION_PROCESSED", "MODEL_PREDICTION", "ALERT_CREATED",
        "INVESTIGATOR_ACTION", "SAR_FILED", "KYC_UPDATED"
    ]
    events = []
    for i in range(_rng.randint(4, 12)):
        events.append({
            "event_id":     _uid(),
            "entity_id":    entity_id,
            "entity_type":  "TRANSACTION",
            "event_type":   _rng.choice(event_types),
            "actor":        f"system-{_rng.choice(['ml','kyc','alert','case'])}",
            "payload_hash": f"sha256:{uuid.UUID(int=_rng.getrandbits(128)).hex}",
            "tx_id":        f"fabric-{uuid.UUID(int=_rng.getrandbits(128)).hex[:16]}",
            "block_number": _rng.randint(1000, 50000),
            "timestamp":    _ts(hours_ago=_rng.uniform(0, 72)),
            "channel":      _rng.choice(["audit-channel", "alert-channel", "kyc-channel"]),
        })
    events.sort(key=lambda e: e["timestamp"])
    return {"entity_id": entity_id, "events": events, "total": len(events)}

def mock_compliance_report(start_date: str, end_date: str) -> dict:
    return {
        "period":                  {"start": start_date, "end": end_date},
        "total_transactions":      14_823,
        "flagged_transactions":    342,
        "flagged_rate":            0.0231,
        "sars_filed":              18,
        "confirmed_fraud":         67,
        "false_positives":         89,
        "avg_detection_latency_ms": 412,
        "blockchain_receipts":     14_823,
        "orgs_validated":          3,
        "majority_consensus_rate": 0.9997,
        "channels": {
            "audit-channel":  {"events": 14_823, "sars": 18},
            "alert-channel":  {"events": 342, "escalated": 28},
            "kyc-channel":    {"events": 156, "risk_updates": 42},
        },
    }

# ── Time-series Analytics ─────────────────────────────────────────────────────

def mock_daily_alerts(days: int = 30) -> list[dict]:
    rows = []
    base = datetime.utcnow()
    for d in range(days, 0, -1):
        dt = base - timedelta(days=d)
        total = _rng.randint(5, 45)
        critical = _rng.randint(0, 6)
        high = _rng.randint(1, 12)
        medium = _rng.randint(2, 18)
        low = total - critical - high - medium
        rows.append({
            "date":       dt.strftime("%Y-%m-%d"),
            "total":      total,
            "critical":   critical,
            "high":       high,
            "medium":     medium,
            "low":        max(low, 0),
            "resolved":   _rng.randint(3, total),
            "false_pos":  _rng.randint(0, 4),
        })
    return rows

def mock_risk_distribution() -> dict:
    return {
        "LOW":      3240,
        "MEDIUM":   1820,
        "HIGH":     640,
        "CRITICAL": 180,
    }

def mock_geo_risk() -> list[dict]:
    return [
        {"country": "United States", "code": "US", "alerts": 38, "risk": "LOW"},
        {"country": "United Kingdom", "code": "GB", "alerts": 24, "risk": "LOW"},
        {"country": "Germany",        "code": "DE", "alerts": 19, "risk": "LOW"},
        {"country": "Nigeria",        "code": "NG", "alerts": 71, "risk": "HIGH"},
        {"country": "Russia",         "code": "RU", "alerts": 58, "risk": "HIGH"},
        {"country": "China",          "code": "CN", "alerts": 44, "risk": "MEDIUM"},
        {"country": "Singapore",      "code": "SG", "alerts": 12, "risk": "LOW"},
        {"country": "UAE",            "code": "AE", "alerts": 33, "risk": "MEDIUM"},
        {"country": "Brazil",         "code": "BR", "alerts": 29, "risk": "MEDIUM"},
        {"country": "Japan",          "code": "JP", "alerts": 8,  "risk": "LOW"},
    ]

def mock_transaction_volume(days: int = 14) -> list[dict]:
    rows = []
    base = datetime.utcnow()
    for d in range(days, 0, -1):
        dt = base - timedelta(days=d)
        rows.append({
            "date":          dt.strftime("%Y-%m-%d"),
            "total_count":   _rng.randint(800, 2400),
            "total_volume":  round(_rng.uniform(1_500_000, 8_000_000), 2),
            "flagged_count": _rng.randint(8, 55),
            "avg_amount":    round(_rng.uniform(3200, 12000), 2),
        })
    return rows
