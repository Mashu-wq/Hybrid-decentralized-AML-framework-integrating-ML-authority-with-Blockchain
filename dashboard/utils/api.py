import requests

KYC_URL        = "http://localhost:9001"
ALERT_URL      = "http://localhost:9003"
CASE_URL       = "http://localhost:9004"
BLOCKCHAIN_URL = "http://localhost:9005"
ML_URL         = "http://localhost:8000"
TX_URL         = "http://localhost:9002"

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
        return None, str(e)

def _post(url, body):
    try:
        r = requests.post(url, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)

def _patch(url, body):
    try:
        r = requests.patch(url, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)

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

# ── KYC ─────────────────────────────────────────────────────────────────────

def get_customers(status=None, limit=50):
    params = {"limit": limit}
    if status:
        params["status"] = status
    return _get(f"{KYC_URL}/api/v1/kyc/customers", params)

def get_customer(customer_id):
    return _get(f"{KYC_URL}/api/v1/kyc/customers/{customer_id}")

def update_kyc_status(customer_id, status, risk_level, verifier_id, reason):
    return _patch(
        f"{KYC_URL}/api/v1/kyc/customers/{customer_id}/status",
        {"status": status, "risk_level": risk_level,
         "verifier_id": verifier_id, "reason": reason}
    )

# ── Alerts ───────────────────────────────────────────────────────────────────

def get_alerts(status=None, min_fraud_prob=None, limit=50):
    params = {"limit": limit}
    if status:
        params["status"] = status
    if min_fraud_prob is not None:
        params["min_fraud_prob"] = min_fraud_prob
    return _get(f"{ALERT_URL}/alerts", params)

def get_alert(alert_id):
    return _get(f"{ALERT_URL}/alerts/{alert_id}")

def get_alerts_for_customer(customer_id, limit=20):
    return _get(f"{ALERT_URL}/alerts/customer/{customer_id}", {"limit": limit})

def get_alert_stats():
    return _get(f"{ALERT_URL}/alerts/stats")

def assign_alert(alert_id, assignee_id):
    return _post(f"{ALERT_URL}/alerts/{alert_id}/assign", {"assignee_id": assignee_id})

def escalate_alert(alert_id, analyst_id, reason):
    return _post(f"{ALERT_URL}/alerts/{alert_id}/escalate",
                 {"analyst_id": analyst_id, "reason": reason})

# ── Cases ────────────────────────────────────────────────────────────────────

def get_cases(status=None, customer_id=None, limit=50):
    params = {"limit": limit}
    if status:
        params["status"] = status
    if customer_id:
        params["customer_id"] = customer_id
    return _get(f"{CASE_URL}/cases", params)

def get_case(case_id):
    return _get(f"{CASE_URL}/cases/{case_id}")

def create_case(body):
    return _post(f"{CASE_URL}/cases", body)

def update_case_status(case_id, status, updated_by, notes):
    return _patch(f"{CASE_URL}/cases/{case_id}/status",
                  {"status": status, "updated_by": updated_by, "notes": notes})

def generate_sar(case_id, generated_by, notes):
    return _post(f"{CASE_URL}/cases/{case_id}/sar",
                 {"generated_by": generated_by, "notes": notes})

# ── Blockchain ───────────────────────────────────────────────────────────────

def get_kyc_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/kyc/record/{customer_id}")

def get_kyc_history_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/kyc/history/{customer_id}")

def get_alerts_on_chain(customer_id):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/alerts/customer/{customer_id}")

def get_audit_trail(entity_id, entity_type):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/trail",
                {"entity_id": entity_id, "entity_type": entity_type})

def get_compliance_report(start_date, end_date):
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/audit/compliance",
                {"start_date": start_date, "end_date": end_date})

def get_alert_stats_on_chain():
    return _get(f"{BLOCKCHAIN_URL}/internal/v1/alerts/stats")

# ── ML ───────────────────────────────────────────────────────────────────────

def get_ml_health():
    return _get(f"{ML_URL}/health")
