import requests
from datetime import datetime, timedelta

KYC_URL        = "http://localhost:9001"
ALERT_URL      = "http://localhost:9003"
CASE_URL       = "http://localhost:9004"
BLOCKCHAIN_URL = "http://localhost:9005"
ML_URL         = "http://localhost:8000"
TX_URL         = "http://localhost:9002"
ANALYTICS_URL  = "http://localhost:9006"

# ── Analytics ─────────────────────────────────────────────────────────────────

def get_fraud_trends(period="7d", granularity="day"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/trends",
                {"period": period, "granularity": granularity})

def get_risk_distribution(period="7d"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/risk-distribution", {"period": period})

def get_top_customers(period="7d", limit=10):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/top-customers",
                {"period": period, "limit": limit})

def get_alert_metrics(period="24h"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/alert-metrics", {"period": period})

def get_transaction_volume(period="7d", granularity="day"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/transaction-volume",
                {"period": period, "granularity": granularity})

def get_geo_distribution(period="7d"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/geo-distribution", {"period": period})

def get_model_performance_live(period="7d", model_version=""):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/model-performance",
                {"period": period, "model_version": model_version})

def get_analytics_report(report_type="SUMMARY", period="7d"):
    return _get(f"{ANALYTICS_URL}/api/v1/analytics/report",
                {"type": report_type, "period": period})

TIMEOUT = 5

def _get(url, params=None):
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except requests.exceptions.ConnectionError:
        return None, "Service unavailable"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        # Surface the server's JSON error body (e.g. "...record ... not found")
        # rather than the raw "400 Client Error" string, so callers can react.
        return None, _extract_error(e)

def _extract_error(e):
    """Return the most informative error string from an exception."""
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            body = resp.json()
            return body.get("message") or body.get("error") or str(e)
        except Exception:
            pass
    return str(e)

def _post(url, body):
    try:
        r = requests.post(url, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, _extract_error(e)

def _patch(url, body):
    try:
        r = requests.patch(url, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, _extract_error(e)

# ── Health ──────────────────────────────────────────────────────────────────

def health_all():
    services = {
        "KYC Service":         f"{KYC_URL}/health",
        "Alert Service":       f"{ALERT_URL}/health",
        "Case Service":        f"{CASE_URL}/health",
        "Blockchain Service":  f"{BLOCKCHAIN_URL}/health",
        "ML Service":          f"{ML_URL}/health",
        "Transaction Service": f"{TX_URL}/health",
    }
    results = {}
    for name, url in services.items():
        data, err = _get(url)
        results[name] = "🟢 Online" if data else "🔴 Offline"
    return results

def health_detail(service_name):
    url_map = {
        "kyc":         f"{KYC_URL}/health",
        "alert":       f"{ALERT_URL}/health",
        "case":        f"{CASE_URL}/health",
        "blockchain":  f"{BLOCKCHAIN_URL}/health",
        "ml":          f"{ML_URL}/health",
        "transaction": f"{TX_URL}/health",
    }
    url = url_map.get(service_name.lower())
    if not url:
        return None, "Unknown service"
    return _get(url)

# ── KYC ─────────────────────────────────────────────────────────────────────

def get_customers(status=None, limit=50):
    params = {"limit": limit}
    if status:
        params["status"] = status
    return _get(f"{KYC_URL}/api/v1/kyc/customers", params)

def get_customer(customer_id):
    return _get(f"{KYC_URL}/api/v1/kyc/customers/{customer_id}")

def register_customer(body):
    return _post(f"{KYC_URL}/api/v1/kyc/customers", body)

def update_kyc_status(customer_id, status, risk_level, verifier_id, reason):
    return _patch(
        f"{KYC_URL}/api/v1/kyc/customers/{customer_id}/status",
        {"status": status, "risk_level": risk_level,
         "verifier_id": verifier_id, "reason": reason}
    )

def get_customer_pii(customer_id, reason="dashboard-review"):
    return _get(
        f"{KYC_URL}/api/v1/kyc/customers/{customer_id}/pii",
        {"reason": reason},
    )

def submit_document(customer_id, doc_type, s3_key, content_type="application/pdf", is_front=True):
    return _post(
        f"{KYC_URL}/api/v1/kyc/customers/{customer_id}/documents",
        {"document_type": doc_type, "s3_key": s3_key,
         "content_type": content_type, "is_front": is_front}
    )

# ── Alerts ───────────────────────────────────────────────────────────────────

def get_alerts(status=None, min_fraud_prob=None, limit=50, offset=0):
    params = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    if min_fraud_prob is not None:
        params["min_fraud_prob"] = min_fraud_prob
    return _get(f"{ALERT_URL}/alerts", params)

def get_alert(alert_id):
    return _get(f"{ALERT_URL}/alerts/{alert_id}")

def get_alerts_for_customer(customer_id, limit=20):
    return _get(f"{ALERT_URL}/alerts/customer/{customer_id}", {"limit": limit})

def get_alert_stats(period="24h"):
    return _get(f"{ALERT_URL}/alerts/stats", {"period": period})

def assign_alert(alert_id, assignee_id):
    return _post(f"{ALERT_URL}/alerts/{alert_id}/assign", {"assignee_id": assignee_id})

def escalate_alert(alert_id, analyst_id, reason):
    return _post(f"{ALERT_URL}/alerts/{alert_id}/escalate",
                 {"analyst_id": analyst_id, "reason": reason})

def update_alert_status(alert_id, status, changed_by="dashboard", notes=""):
    return _patch(f"{ALERT_URL}/alerts/{alert_id}/status",
                  {"status": status, "changed_by": changed_by, "notes": notes})

# ── Cases ────────────────────────────────────────────────────────────────────

# The case-service serialises case objects in PascalCase (CaseID, Title, …)
# whereas the rest of the dashboard (and the alert-service) use snake_case.
# Normalise here so pages can use a single, consistent snake_case convention.
_CASE_FIELD_MAP = {
    "CaseID": "case_id", "AlertID": "alert_id", "CustomerID": "customer_id",
    "TxHash": "tx_hash", "Title": "title", "Description": "description",
    "Status": "status", "Priority": "priority", "AssigneeID": "assignee_id",
    "AssignedAt": "assigned_at", "FraudProbability": "fraud_probability",
    "RiskScore": "risk_score", "SARRequired": "sar_required",
    "SARS3Key": "sar_s3_key", "SARGeneratedAt": "sar_generated_at",
    "BlockchainTxID": "blockchain_tx_id", "ResolutionSummary": "resolution_summary",
    "ClosedAt": "closed_at", "CreatedAt": "created_at", "UpdatedAt": "updated_at",
}

def _normalize_case(c):
    """Return a case dict with snake_case keys (originals preserved too)."""
    if not isinstance(c, dict):
        return c
    out = dict(c)
    for k, v in c.items():
        out[_CASE_FIELD_MAP.get(k, k)] = v
    return out

def get_cases(status=None, customer_id=None, limit=50):
    params = {"limit": limit}
    if status:
        params["status"] = status
    if customer_id:
        params["customer_id"] = customer_id
    data, err = _get(f"{CASE_URL}/cases", params)
    if isinstance(data, dict) and isinstance(data.get("cases"), list):
        data["cases"] = [_normalize_case(c) for c in data["cases"]]
    return data, err

def get_case(case_id):
    data, err = _get(f"{CASE_URL}/cases/{case_id}")
    if isinstance(data, dict):
        # detail is wrapped as {"case": {...}, "actions": [...]}
        case = data.get("case", data)
        norm = _normalize_case(case)
        if "actions" in data:
            norm["actions"] = data["actions"]
        return norm, err
    return data, err

def create_case(body):
    return _post(f"{CASE_URL}/cases", body)

def update_case_status(case_id, status, updated_by, notes):
    return _patch(f"{CASE_URL}/cases/{case_id}/status",
                  {"status": status, "updated_by": updated_by, "notes": notes})

def generate_sar(case_id, generated_by, notes):
    return _post(f"{CASE_URL}/cases/{case_id}/sar",
                 {"generated_by": generated_by, "notes": notes})

def get_case_stats(period="7d"):
    return _get(f"{CASE_URL}/cases/stats", {"period": period})

# ── Transactions ─────────────────────────────────────────────────────────────
# NOTE: the transaction-service exposes ONLY /health over HTTP (port 9002);
# transaction reads (GetTransaction, GetRiskScore, GetVelocityStats, history)
# are served over gRPC on :50062, not REST. The helpers below will 404 until a
# REST gateway is added — they are currently unused by any dashboard page.

def get_transaction(tx_hash):
    return _get(f"{TX_URL}/transactions/{tx_hash}")

def get_customer_transactions(customer_id, limit=50):
    return _get(f"{TX_URL}/transactions/customer/{customer_id}", {"limit": limit})

def get_risk_score(customer_id):
    return _get(f"{TX_URL}/risk-score/{customer_id}")

def get_velocity_stats(customer_id):
    return _get(f"{TX_URL}/velocity/{customer_id}")

# ── Blockchain ───────────────────────────────────────────────────────────────

def get_kyc_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/kyc/record/{customer_id}")

def get_kyc_history_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/kyc/history/{customer_id}")

def get_alerts_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/alerts/customer/{customer_id}")

def get_audit_trail(entity_id, entity_type):
    # Blockchain service wraps results as {"transaction_id": ..., "payload": [...]}.
    # Return the payload (the list of audit records) directly.
    data, err = _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/trail",
                     {"entity_id": entity_id, "entity_type": entity_type})
    if isinstance(data, dict) and "payload" in data:
        return data["payload"], err
    return data, err

def get_compliance_report(start_date, end_date):
    # Wrapped as {"transaction_id": ..., "payload": {...}} — return the payload dict.
    data, err = _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/compliance",
                     {"start_date": start_date, "end_date": end_date})
    if isinstance(data, dict) and "payload" in data:
        return data["payload"], err
    return data, err

def get_alert_stats_on_chain():
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/alerts/stats")

def get_blockchain_health():
    return _get(f"{BLOCKCHAIN_URL}/health")

def get_audit_sequence_status():
    # Latest chaincode-assigned receipt sequence per org (gap-free by construction).
    # Wrapped as {"transaction_id": ..., "payload": [...]} — return the payload list.
    data, err = _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/sequence")
    if isinstance(data, dict) and "payload" in data:
        return data["payload"], err
    return data, err

def get_audit_completeness(expected_count):
    # Reconcile on-chain receipt count vs the bank's independently sourced
    # transaction count. Returns {msp_id, anchored_receipts, expected_count,
    # missing_receipts, complete}.
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/completeness",
                {"expected_count": int(expected_count)})

def get_receipt_details_on_chain(record_id):
    # Private half of a processing receipt (bank+regulator Private Data
    # Collection), hash-verified by the chaincode against the public record.
    data, err = _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/receipt-details/{record_id}")
    if isinstance(data, dict) and "payload" in data:
        return data["payload"], err
    return data, err

# ── ML ───────────────────────────────────────────────────────────────────────

def get_ml_health():
    return _get(f"{ML_URL}/health")

def predict_fraud(features: dict, model: str = ""):
    return _post(f"{ML_URL}/api/v1/predict", {"features": features, "model": model})

def predict_fraud_batch(features_list: list, model: str = ""):
    return _post(f"{ML_URL}/api/v1/predict/batch", {"features_list": features_list, "model": model})

def get_model_metrics(model_name: str = ""):
    params = {}
    if model_name:
        params["model_name"] = model_name
    return _get(f"{ML_URL}/api/v1/model/metrics", params)

def get_model_comparison():
    return _get(f"{ML_URL}/api/v1/model/comparison")

def explain_lime(prediction_id: str, num_features: int = 10):
    return _post(f"{ML_URL}/api/v1/explain/lime",
                 {"prediction_id": prediction_id, "num_features": num_features})

def explain_counterfactual(prediction_id: str, target_prob: float = 0.3):
    return _post(f"{ML_URL}/api/v1/explain/counterfactual",
                 {"prediction_id": prediction_id, "target_prob": target_prob})
