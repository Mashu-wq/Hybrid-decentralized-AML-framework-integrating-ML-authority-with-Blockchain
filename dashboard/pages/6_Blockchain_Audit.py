"""
Blockchain Audit Trail Page
Query the Hyperledger Fabric audit-channel for transaction receipts,
model predictions, SAR filings, and KYC events. View compliance reports.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta

from utils import api

st.set_page_config(page_title="Blockchain Audit", page_icon="⛓️", layout="wide")

EVENT_COLORS = {
    "TRANSACTION_PROCESSED": "#3b82f6",
    "MODEL_PREDICTION":      "#a855f7",
    "ALERT_CREATED":         "#f97316",
    "INVESTIGATOR_ACTION":   "#eab308",
    "SAR_FILED":             "#ef4444",
    "KYC_UPDATED":           "#22c55e",
}
CHANNEL_COLORS = {
    "audit-channel": "#3b82f6",
    "alert-channel": "#f97316",
    "kyc-channel":   "#22c55e",
}

st.markdown("# ⛓️ Blockchain Audit Trail")
st.markdown(
    "Immutable audit ledger on **Hyperledger Fabric** — 3 orgs · 3 channels · "
    "MAJORITY block validation. Commit latency ~400–900 ms."
)
st.markdown("---")

# ── Network Status ─────────────────────────────────────────────────────────────
st.subheader("Fabric Network Status")
bc_health, bc_err = api.get_blockchain_health()

if bc_health:
    st.success("Blockchain Service Online ✓")
    details = bc_health.get("details", {})
    if isinstance(details, dict) and details:
        cols = st.columns(len(details))
        for col, (channel, val) in zip(cols, details.items()):
            block_height = str(val).split("block_height=")[-1] if "block_height=" in str(val) else str(val)
            col.metric(channel, f"Block #{block_height}")
    else:
        st.json(bc_health)
else:
    st.error(f"Blockchain service offline: {bc_err}. Start with `make fabric-up && make chaincode-deploy`.")
    st.stop()

st.markdown("---")

tab_trail, tab_compliance, tab_explorer = st.tabs([
    "Audit Trail", "Compliance Report", "Architecture"
])

# ── Tab 1: Audit Trail ────────────────────────────────────────────────────────
with tab_trail:
    st.subheader("Entity Audit Trail Query")
    st.markdown(
        "Look up the immutable event history for any entity "
        "(transaction hash, customer ID, case ID, alert ID)."
    )

    c1, c2 = st.columns(2)
    with c1:
        entity_id = st.text_input("Entity ID",
            placeholder="Transaction hash / Customer ID / Case ID…")
    with c2:
        entity_type = st.selectbox("Entity Type",
            ["TRANSACTION", "CUSTOMER", "ALERT", "CASE", "SAR"])

    if st.button("Query Audit Trail", type="primary") and entity_id.strip():
        trail_data, trail_err = api.get_audit_trail(entity_id.strip(), entity_type)

        if trail_data:
            events = trail_data.get("events", []) if isinstance(trail_data, dict) else trail_data
        else:
            st.error(f"Blockchain service unavailable: {trail_err}. Start with `make fabric-up` then `make chaincode-deploy`.")
            st.stop()

        if not events:
            st.info("No audit events found for this entity.")
        else:
            st.success(f"Found **{len(events)}** on-chain events for `{entity_id.strip()}`")

            # Timeline chart
            df_ev = pd.DataFrame(events)
            if "timestamp" in df_ev.columns and "event_type" in df_ev.columns:
                df_ev["ts"] = pd.to_datetime(df_ev["timestamp"])
                df_ev["y"]  = 1

                fig_tl = px.scatter(
                    df_ev, x="ts", y="y",
                    color="event_type",
                    color_discrete_map=EVENT_COLORS,
                    hover_data=["event_type","block_number","channel","actor"] if "block_number" in df_ev.columns else ["event_type"],
                    labels={"ts": "Timestamp", "y": ""},
                    title="Event Timeline",
                )
                fig_tl.update_traces(marker_size=14)
                fig_tl.update_yaxes(visible=False)
                fig_tl.update_layout(
                    template="plotly_dark",
                    plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                    height=220, margin=dict(t=40, b=0, l=0, r=0),
                    legend=dict(orientation="h", y=1.2),
                )
                st.plotly_chart(fig_tl, use_container_width=True)

            # Event cards
            for ev in events:
                ev_type = ev.get("event_type", "—")
                color   = EVENT_COLORS.get(ev_type, "#6b7280")
                st.markdown(
                    f"<div style='background:#1a1d27;border-left:4px solid {color};"
                    f"border-radius:6px;padding:12px 16px;margin-bottom:8px'>"
                    f"<div style='display:flex;justify-content:space-between'>"
                    f"<span style='color:{color};font-weight:700;font-size:0.9rem'>{ev_type}</span>"
                    f"<span style='color:#9ca3af;font-size:0.8rem'>"
                    f"{ev.get('timestamp','—')}</span></div>"
                    f"<div style='color:#d1d5db;font-size:0.82rem;margin-top:6px'>"
                    f"Block: <b>{ev.get('block_number','—')}</b> · "
                    f"Channel: <b>{ev.get('channel','—')}</b> · "
                    f"Actor: <b>{ev.get('actor','—')}</b></div>"
                    f"<div style='color:#6b7280;font-size:0.75rem;margin-top:4px'>"
                    f"TX: {ev.get('tx_id',ev.get('fabric_tx_id','—'))} · "
                    f"Hash: {ev.get('payload_hash','—')}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

# ── Tab 2: Compliance Report ───────────────────────────────────────────────────
with tab_compliance:
    st.subheader("Regulatory Compliance Report")
    st.markdown(
        "Generates an auditable compliance summary anchored to the **audit-channel** ledger. "
        "All metrics are independently verifiable by the Org2 (Regulator) peer."
    )

    c1, c2 = st.columns(2)
    with c1:
        start_dt = st.date_input("Start Date", value=datetime.utcnow().date() - timedelta(days=30))
    with c2:
        end_dt   = st.date_input("End Date",   value=datetime.utcnow().date())

    if st.button("Generate Report", type="primary"):
        start_str = start_dt.isoformat() + "T00:00:00Z"
        end_str   = end_dt.isoformat()   + "T23:59:59Z"

        report, rep_err = api.get_compliance_report(start_str, end_str)
        if not report:
            st.error(f"Blockchain service unavailable: {rep_err}. Start with `make fabric-up` then `make chaincode-deploy`.")
            st.stop()

        st.success("Compliance report generated ✓")

        # KPIs
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Transactions", f"{report.get('total_transactions',0):,}")
        k2.metric("Flagged",            f"{report.get('flagged_transactions',0):,}")
        k3.metric("Flag Rate",          f"{report.get('flagged_rate',0)*100:.2f}%")
        k4.metric("SARs Filed",         report.get("sars_filed",0))
        k5.metric("Blockchain Receipts",f"{report.get('blockchain_receipts',0):,}")

        k6, k7, k8 = st.columns(3)
        k6.metric("Confirmed Fraud",    report.get("confirmed_fraud",0))
        k7.metric("False Positives",    report.get("false_positives",0))
        k8.metric("Consensus Rate",
                  f"{report.get('majority_consensus_rate',0)*100:.3f}%")

        # Channel breakdown
        st.markdown("---")
        st.markdown("#### Channel Breakdown")
        channels = report.get("channels", {})
        ch_df = pd.DataFrame([
            {"Channel": ch, **vals} for ch, vals in channels.items()
        ])
        if not ch_df.empty:
            st.dataframe(ch_df, use_container_width=True, hide_index=True)

        # Detection funnel chart
        st.markdown("---")
        st.markdown("#### Detection Funnel")
        funnel_vals = [
            report.get("total_transactions", 0),
            report.get("flagged_transactions", 0),
            report.get("confirmed_fraud", 0) + report.get("false_positives", 0),
            report.get("confirmed_fraud", 0),
            report.get("sars_filed", 0),
        ]
        funnel_labels = [
            "Total Transactions",
            "ML Flagged",
            "Investigated",
            "Confirmed Fraud",
            "SAR Filed",
        ]
        fig_f = go.Figure(go.Funnel(
            y=funnel_labels,
            x=funnel_vals,
            textinfo="value+percent initial",
            marker_color=["#3b82f6","#f97316","#eab308","#ef4444","#a855f7"],
        ))
        fig_f.update_layout(
            template="plotly_dark",
            plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            height=340, margin=dict(t=10, b=0, l=0, r=0),
        )
        st.plotly_chart(fig_f, use_container_width=True)

        # Full report JSON
        with st.expander("View Full JSON Report"):
            st.json(report)

# ── Tab 3: Architecture ────────────────────────────────────────────────────────
with tab_explorer:
    st.subheader("Fabric Network Architecture")

    col_l, col_r = st.columns([1, 1])

    with col_l:
        st.markdown("""
        #### Network Topology

        | Component | Count | Detail |
        |-----------|-------|--------|
        | Organizations | 3 | PrimaryBank · Regulator · PartnerBank |
        | Orderers | 3 | One per org, Raft consensus |
        | Channels | 3 | kyc · alert · audit |
        | Block Policy | MAJORITY | ≥2 of 3 orgs must sign |
        | Commit Latency | ~400–900ms | Measured on dev network |

        #### Channels

        | Channel | Chaincode | Key Functions |
        |---------|-----------|---------------|
        | `kyc-channel` | kyc-contract | RegisterCustomer, UpdateKYCStatus |
        | `alert-channel` | alert-contract | CreateAlert, UpdateAlertStatus |
        | `audit-channel` | audit-contract | RecordTransactionProcessed, RecordSARFiled, RecordModelPrediction |
        """)

    with col_r:
        st.markdown("""
        #### Privacy Model

        - **Customer PII** never written to ledger — identity stored as `SHA-256(document)`
        - **SAR documents** stored in S3; only `SHA-256(PDF)` anchored on `audit-channel`
        - All 3 orgs are members of all 3 channels (regulatory mandate)
        - **PDC** (Private Data Collections) identified as future work for feature-level isolation

        #### Fabrication Gap Closure

        `RecordTransactionProcessed` is called for **every** ML-scored transaction
        (not just flagged ones). The regulator's peer independently holds the full
        `audit-channel` ledger — absence of a receipt is detectable without trusting
        the bank.

        #### Audit Event Types

        | Event | Channel | Trigger |
        |-------|---------|---------|
        | `TRANSACTION_PROCESSED` | audit | Every ML prediction |
        | `MODEL_PREDICTION` | audit | SHAP values persisted |
        | `ALERT_CREATED` | alert | Fraud threshold breached |
        | `INVESTIGATOR_ACTION` | audit | Case update |
        | `SAR_FILED` | audit | SAR PDF generated |
        | `KYC_UPDATED` | kyc | Status change |
        """)

    # Org sankey diagram
    st.markdown("---")
    st.markdown("#### Data Flow: Transaction → Blockchain")
    fig_sankey = go.Figure(go.Sankey(
        node=dict(
            pad=15, thickness=20,
            label=["Transaction", "ML Service", "Alert Service", "Blockchain Service",
                   "audit-channel", "alert-channel", "kyc-channel",
                   "PrimaryBank", "Regulator", "PartnerBank"],
            color=["#3b82f6","#a855f7","#f97316","#22c55e",
                   "#3b82f6","#f97316","#22c55e",
                   "#1a1d27","#1a1d27","#1a1d27"],
        ),
        link=dict(
            source=[0, 0, 1, 1, 2, 3, 3, 3, 4, 4, 5, 6],
            target=[1, 2, 3, 3, 3, 4, 5, 6, 7, 8, 9, 8],
            value= [10,4, 10,4, 4, 10,4, 2, 5, 5, 4, 2],
            color=["rgba(59,130,246,0.3)"] * 12,
        ),
    ))
    fig_sankey.update_layout(
        template="plotly_dark",
        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
        height=360, margin=dict(t=10, b=0, l=0, r=0),
    )
    st.plotly_chart(fig_sankey, use_container_width=True)
