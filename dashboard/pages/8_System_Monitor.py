"""
System Monitor Page
Live service health checks, endpoint latency testing, configuration reference,
and links to Grafana / Jaeger / MLflow / Vault external monitoring.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import time
import json
from datetime import datetime

from utils import api

st.set_page_config(page_title="System Monitor", page_icon="🖥️", layout="wide")

st.markdown("# 🖥️ System Monitor")
st.markdown("Live service health, latency probes, and infrastructure reference.")
st.markdown("---")

# ── Refresh Controls ──────────────────────────────────────────────────────────
col_ref, col_info = st.columns([1, 3])
with col_ref:
    auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)
with col_info:
    st.caption(
        "Health checks hit each service's `/health` endpoint. "
        "Services use the ports configured in CLAUDE.md § 8."
    )

# ── Service Health Grid ────────────────────────────────────────────────────────
st.subheader("Service Health")

SERVICE_CONFIG = {
    "API Gateway":         ("http://localhost:8080", "Go"),
    "IAM Service":         ("http://localhost:9000", "Go gRPC :50060"),
    "KYC Service":         ("http://localhost:9001", "Go gRPC :50061"),
    "Transaction Service": ("http://localhost:9002", "Go gRPC :50062"),
    "Alert Service":       ("http://localhost:9003", "Go gRPC :50063"),
    "Case Service":        ("http://localhost:9004", "Go gRPC :50064"),
    "Blockchain Service":  ("http://localhost:9005", "Go HTTP"),
    "ML Service":          ("http://localhost:8000", "Python FastAPI"),
}

HEALTH_URLS = {
    "API Gateway":         "http://localhost:8080/health",
    "IAM Service":         "http://localhost:9000/health",
    "KYC Service":         f"{api.KYC_URL}/health",
    "Transaction Service": f"{api.TX_URL}/health",
    "Alert Service":       f"{api.ALERT_URL}/health",
    "Case Service":        f"{api.CASE_URL}/health",
    "Blockchain Service":  f"{api.BLOCKCHAIN_URL}/health",
    "ML Service":          f"{api.ML_URL}/health",
}

if "health_results" not in st.session_state or st.button("Refresh Now", type="primary"):
    import requests
    results = {}
    for name, url in HEALTH_URLS.items():
        t0 = time.perf_counter()
        try:
            r = requests.get(url, timeout=3)
            latency_ms = (time.perf_counter() - t0) * 1000
            if r.ok:
                results[name] = {
                    "status": "online",
                    "latency_ms": round(latency_ms, 1),
                    "detail": r.json() if r.headers.get("content-type","").startswith("application/json") else str(r.text[:100]),
                }
            else:
                results[name] = {"status": "error", "latency_ms": round(latency_ms,1),
                                 "detail": f"HTTP {r.status_code}"}
        except Exception as e:
            results[name] = {"status": "offline", "latency_ms": None,
                             "detail": str(e)[:80]}
    st.session_state["health_results"] = results
    st.session_state["health_ts"] = datetime.utcnow().strftime("%H:%M:%S UTC")

results = st.session_state.get("health_results", {})
health_ts = st.session_state.get("health_ts", "—")

cols = st.columns(3)
for i, (name, url_info) in enumerate(SERVICE_CONFIG.items()):
    url, stack = url_info
    res = results.get(name, {})
    status     = res.get("status", "unknown")
    latency_ms = res.get("latency_ms")

    color  = {"online":"#22c55e","offline":"#ef4444","error":"#f97316","unknown":"#6b7280"}[status]
    icon   = {"online":"🟢","offline":"🔴","error":"🟠","unknown":"⚪"}[status]
    lat_str = f"{latency_ms:.0f} ms" if latency_ms is not None else "—"

    with cols[i % 3]:
        st.markdown(
            f"<div style='background:#1a1d27;border:1px solid {color};border-radius:8px;"
            f"padding:14px;margin-bottom:12px'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center'>"
            f"<span style='font-weight:700;color:#f9fafb'>{icon} {name}</span>"
            f"<span style='color:{color};font-size:0.82rem;font-weight:600'>"
            f"{status.upper()}</span></div>"
            f"<div style='color:#6b7280;font-size:0.78rem;margin-top:4px'>"
            f"{stack}</div>"
            f"<div style='color:#9ca3af;font-size:0.82rem;margin-top:6px'>"
            f"Latency: <b style='color:{color}'>{lat_str}</b> · {url}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

st.caption(f"Last checked: {health_ts}")

# ── Latency Chart ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("Endpoint Latency (ms)")

latency_data = {
    name: res.get("latency_ms", 0) or 0
    for name, res in results.items()
    if res.get("status") == "online"
}

if latency_data:
    services_l = list(latency_data.keys())
    latencies  = list(latency_data.values())
    colors_l   = ["#22c55e" if v < 50 else "#eab308" if v < 200 else "#ef4444"
                  for v in latencies]
    fig_lat = go.Figure(go.Bar(
        x=services_l, y=latencies,
        marker_color=colors_l,
        text=[f"{v:.0f} ms" for v in latencies],
        textposition="outside",
    ))
    fig_lat.update_layout(
        template="plotly_dark",
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        yaxis_title="Latency (ms)",
        height=280, margin=dict(t=10, b=0, l=0, r=0),
        showlegend=False,
    )
    st.plotly_chart(fig_lat, use_container_width=True)
else:
    st.info("No services online — latency chart unavailable.")

st.markdown("---")

# ── Infrastructure Reference ───────────────────────────────────────────────────
tab_ports, tab_ext, tab_config = st.tabs([
    "Service Ports", "External Tools", "Service Detail"
])

with tab_ports:
    st.subheader("Service Port Reference")
    port_data = [
        {"Service": "API Gateway",        "HTTP Port": 8080, "gRPC Port": "—",   "Stack": "Go"},
        {"Service": "IAM Service",         "HTTP Port": "—",  "gRPC Port": 50060, "Stack": "Go"},
        {"Service": "KYC Service",         "HTTP Port": 9001, "gRPC Port": 50061, "Stack": "Go"},
        {"Service": "Transaction Service", "HTTP Port": 9002, "gRPC Port": 50062, "Stack": "Go"},
        {"Service": "Alert Service",       "HTTP Port": 9003, "gRPC Port": 50063, "Stack": "Go"},
        {"Service": "Case Service",        "HTTP Port": 9004, "gRPC Port": 50064, "Stack": "Go"},
        {"Service": "Analytics Service",   "HTTP Port": 9006, "gRPC Port": 50065, "Stack": "Go"},
        {"Service": "Blockchain Service",  "HTTP Port": 9005, "gRPC Port": "—",   "Stack": "Go"},
        {"Service": "Encryption Service",  "HTTP Port": "—",  "gRPC Port": 50067, "Stack": "Go"},
        {"Service": "ML Service (REST)",   "HTTP Port": 8000, "gRPC Port": "—",   "Stack": "Python FastAPI"},
        {"Service": "ML Service (gRPC)",   "HTTP Port": "—",  "gRPC Port": 50051, "Stack": "Python"},
    ]
    st.dataframe(pd.DataFrame(port_data), use_container_width=True, hide_index=True)

    st.markdown("#### Data Stores")
    ds_data = [
        {"Store": "PostgreSQL",  "Purpose": "IAM, KYC, Alert, Case (relational records)"},
        {"Store": "MongoDB",     "Purpose": "Transaction Service (time-series enriched transactions)"},
        {"Store": "Redis",       "Purpose": "Velocity windows, JWT cache, risk score TTL"},
        {"Store": "Kafka",       "Purpose": "transactions.raw, alerts.created topics"},
        {"Store": "Vault",       "Purpose": "AES-256-GCM PII encryption at rest"},
        {"Store": "MLflow",      "Purpose": "Model experiment tracking & artifact storage"},
        {"Store": "Prometheus",  "Purpose": "Metrics scraping from all Go services"},
        {"Store": "Grafana",     "Purpose": "Dashboards for service metrics"},
    ]
    st.dataframe(pd.DataFrame(ds_data), use_container_width=True, hide_index=True)

with tab_ext:
    st.subheader("External Monitoring Tools")
    tools = [
        ("Grafana",   "http://localhost:3000",  "admin / see .env", "Service metrics dashboards, alert rules"),
        ("Prometheus","http://localhost:9090",  "—",                "Raw metrics explorer"),
        ("Jaeger",    "http://localhost:16686", "—",                "Distributed tracing (inter-service calls)"),
        ("MLflow",    "http://localhost:5000",  "—",                "Model experiment tracking, artifact browser"),
        ("Vault UI",  "http://localhost:8200",  "Token from .env",  "HashiCorp Vault — transit encryption"),
        ("Kafka UI",  "http://localhost:8090",  "--profile dev-tools","Topic & consumer group monitoring"),
    ]
    for name, url, auth, desc in tools:
        with st.expander(f"{name} — {url}"):
            st.markdown(f"**URL:** `{url}`")
            st.markdown(f"**Auth:** {auth}")
            st.markdown(f"**Purpose:** {desc}")

with tab_config:
    st.subheader("Service Detail & Health Responses")
    for name, res in results.items():
        status = res.get("status", "unknown")
        color  = {"online":"#22c55e","offline":"#ef4444","error":"#f97316","unknown":"#6b7280"}[status]
        with st.expander(f"{name} — {status.upper()}"):
            detail = res.get("detail", "")
            if isinstance(detail, dict):
                st.json(detail)
            elif detail:
                try:
                    st.json(json.loads(detail))
                except Exception:
                    st.code(str(detail))
            else:
                st.info("No response body.")
            if res.get("latency_ms") is not None:
                st.caption(f"Round-trip latency: {res['latency_ms']:.1f} ms")

# ── Auto-refresh logic ─────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(10)
    st.rerun()
