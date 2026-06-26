"""
Overview & System Health Dashboard — fully dynamic, no mock data.
All charts pull from live backend APIs.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime

from utils import api

st.set_page_config(page_title="Overview", page_icon="📊", layout="wide")

st.markdown("# 📊 Platform Overview")
st.markdown("Real-time operational snapshot — all data from live backend APIs.")
st.markdown("---")

# ── Service Health ─────────────────────────────────────────────────────────────
st.subheader("Service Health")
with st.spinner("Checking services…"):
    health = api.health_all()

cols = st.columns(len(health))
for col, (name, status) in zip(cols, health.items()):
    with col:
        is_up  = "Online" in status
        color  = "#22c55e" if is_up else "#ef4444"
        icon   = "🟢" if is_up else "🔴"
        st.markdown(
            f"<div style='background:#1a1d27;border:1px solid {color};border-radius:8px;"
            f"padding:10px;text-align:center'>"
            f"<div style='font-size:1.4rem'>{icon}</div>"
            f"<div style='font-size:0.75rem;color:#9ca3af;margin-top:4px'>{name}</div>"
            f"<div style='font-size:0.85rem;color:{color};font-weight:600'>"
            f"{'Online' if is_up else 'Offline'}</div></div>",
            unsafe_allow_html=True,
        )

st.markdown("---")

# ── KPIs ──────────────────────────────────────────────────────────────────────
st.subheader("Key Performance Indicators")

period_opts = {"Last 24 h": "24h", "Last 7 days": "7d", "Last 30 days": "30d"}
period_sel  = st.selectbox("Period", list(period_opts.keys()), index=0, key="ov_period")
period      = period_opts[period_sel]

alert_stats, a_err = api.get_alert_stats(period)
case_stats,  c_err = api.get_case_stats("7d")

if not alert_stats and not case_stats:
    st.error(
        f"Alert service: {a_err}  |  Case service: {c_err}\n\n"
        "Start the backend services with `make run` to see live data."
    )
    st.stop()

k1, k2, k3, k4, k5, k6 = st.columns(6)
if alert_stats:
    k1.metric("Total Alerts",       alert_stats.get("TotalAlerts",       "—"))
    k2.metric("Critical Alerts",    alert_stats.get("CriticalAlerts",    "—"))
    k3.metric("Open Alerts",        alert_stats.get("OpenAlerts",        "—"))
    k4.metric("FP Rate",            f"{alert_stats.get('FalsePositiveRate',0)*100:.1f}%")
    k5.metric("Avg Resolution (min)",f"{alert_stats.get('AvgResolutionTimeMin',0):.0f}")
if case_stats:
    k6.metric("SARs Generated (7d)",case_stats.get("SARGenerated", "—"))

st.markdown("---")

# ── Alert Trend ────────────────────────────────────────────────────────────────
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Alert Trend")
    trends_data, t_err = api.get_fraud_trends(period=period, granularity="day")
    if trends_data and trends_data.get("points"):
        df = pd.DataFrame(trends_data["points"])
        fig = go.Figure()
        if "fraud_count" in df.columns:
            fig.add_trace(go.Bar(
                x=df["date"], y=df["alert_count"],
                name="Total Alerts", marker_color="#3b82f6",
            ))
            fig.add_trace(go.Bar(
                x=df["date"], y=df["fraud_count"],
                name="Fraud (HIGH+CRITICAL)", marker_color="#ef4444",
            ))
        if "fraud_rate" in df.columns:
            fig.add_trace(go.Scatter(
                x=df["date"], y=(df["fraud_rate"]*100).round(2),
                name="Fraud Rate %", yaxis="y2",
                line=dict(color="#eab308", width=2),
            ))
        fig.update_layout(
            barmode="overlay",
            template="plotly_dark",
            plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            yaxis=dict(title="Alert Count"),
            yaxis2=dict(title="Fraud Rate (%)", overlaying="y", side="right", showgrid=False),
            legend=dict(orientation="h", y=1.1),
            height=320, margin=dict(t=10, b=0, l=0, r=0),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning(f"Alert trend unavailable — Analytics service: {t_err}")

with col_right:
    st.subheader("Risk Distribution")
    dist_data, d_err = api.get_risk_distribution(period=period)
    if dist_data and dist_data.get("buckets"):
        buckets = dist_data["buckets"]
        labels = [b["RiskLevel"] for b in buckets]
        values = [b["Count"] for b in buckets]
        color_map = {"LOW":"#22c55e","MEDIUM":"#eab308","HIGH":"#f97316","CRITICAL":"#ef4444"}
        colors = [color_map.get(l, "#6b7280") for l in labels]
        fig2 = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.55,
            marker_colors=colors,
        ))
        fig2.update_layout(
            template="plotly_dark",
            plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            legend=dict(orientation="h", y=-0.1),
            height=320, margin=dict(t=0, b=0, l=0, r=0),
            annotations=[dict(text=f"Total\n{sum(values):,}", x=0.5, y=0.5,
                              font_size=13, showarrow=False, font_color="#9ca3af")],
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.warning(f"Risk distribution unavailable — {d_err}")

st.markdown("---")

# ── Transaction Volume ─────────────────────────────────────────────────────────
st.subheader("Transaction Volume")
vol_data, v_err = api.get_transaction_volume(period=period, granularity="day")
if vol_data and vol_data.get("points"):
    df_tx = pd.DataFrame(vol_data["points"])
    fig3 = go.Figure()
    fig3.add_trace(go.Bar(
        x=df_tx["date"], y=df_tx["total_count"],
        name="Total Transactions", marker_color="#3b82f6", yaxis="y",
    ))
    fig3.add_trace(go.Scatter(
        x=df_tx["date"], y=df_tx["flagged_count"],
        name="Flagged", line=dict(color="#ef4444", width=2),
        mode="lines+markers", yaxis="y2",
    ))
    fig3.update_layout(
        template="plotly_dark",
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        yaxis=dict(title="Transaction Count"),
        yaxis2=dict(title="Flagged", overlaying="y", side="right", showgrid=False),
        legend=dict(orientation="h", y=1.08),
        height=280, margin=dict(t=10, b=0, l=0, r=0),
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.warning(f"Transaction volume unavailable — Analytics service: {v_err}")

st.markdown("---")

# ── Case Status ───────────────────────────────────────────────────────────────
if case_stats:
    st.subheader("Case Status Breakdown (7d)")
    labels  = ["Open", "In Review", "Pending SAR", "Closed"]
    values  = [
        case_stats.get("OpenCases", 0),
        case_stats.get("InReviewCases", 0),
        case_stats.get("PendingSARCases", 0),
        case_stats.get("ClosedCases", 0),
    ]
    fig4 = go.Figure(go.Bar(
        x=labels, y=values,
        marker_color=["#3b82f6","#a855f7","#eab308","#22c55e"],
        text=values, textposition="outside",
    ))
    fig4.update_layout(
        template="plotly_dark",
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        showlegend=False, height=260, margin=dict(t=10, b=0, l=0, r=0),
    )
    st.plotly_chart(fig4, use_container_width=True)

st.caption(f"Refreshed {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
