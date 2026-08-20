"""Shared risk-level helpers for the dashboard.

Keeps the composite-score → risk-level mapping in ONE place so every page
(Fraud Alerts, KYC Management, …) agrees with the on-chain alert-contract.
"""

PRIORITY_MAP = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNSPECIFIED"}


def risk_level_from_score(score):
    """Derive the alert risk level from the composite risk_score (0-100).

    Mirrors the on-chain alert-contract deriveRiskLevel() thresholds
    (>85 CRITICAL, >=70 HIGH, >=50 MEDIUM, else LOW) so the dashboard badge
    matches the Fabric alert-channel record. The composite score blends ML
    fraud probability with FATF rule signals (KYC tier, merchant, geography)
    and is the correct driver of risk level — not the raw ML probability, which
    is intentionally a minor (10%) input on adapted bank-wire features.
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s > 85:
        return "CRITICAL"
    if s >= 70:
        return "HIGH"
    if s >= 50:
        return "MEDIUM"
    return "LOW"


def alert_risk_level(alert):
    """Best risk level for an alert dict: composite score first, then any
    explicit risk_level string, then the ML-probability-derived priority."""
    if not isinstance(alert, dict):
        return "—"
    return (risk_level_from_score(alert.get("risk_score"))
            or alert.get("risk_level")
            or PRIORITY_MAP.get(alert.get("priority", 0), "—"))
