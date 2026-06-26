"""
AML Fraud Detection — Streamlit Dashboard
Main entry point. Run with:
    streamlit run dashboard/app.py
"""
import streamlit as st

st.set_page_config(
    page_title="AML Fraud Detection Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Sidebar */
[data-testid="stSidebar"] { background: #0f1117; }
[data-testid="stSidebar"] * { color: #e0e0e0 !important; }

/* Metric cards */
[data-testid="stMetric"] {
    background: #1a1d27;
    border: 1px solid #2d3150;
    border-radius: 10px;
    padding: 12px 16px;
}
[data-testid="stMetricLabel"]  { color: #9ca3af !important; font-size: 0.82rem; }
[data-testid="stMetricValue"]  { color: #f9fafb !important; font-size: 1.6rem; }
[data-testid="stMetricDelta"]  { font-size: 0.8rem; }

/* Headers */
h1 { color: #60a5fa; }
h2 { color: #93c5fd; }
h3 { color: #bfdbfe; }

/* Status badges */
.badge-critical { background:#ef4444; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; font-weight:600; }
.badge-high     { background:#f97316; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; font-weight:600; }
.badge-medium   { background:#eab308; color:#1a1a1a; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; font-weight:600; }
.badge-low      { background:#22c55e; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; font-weight:600; }
.badge-open     { background:#3b82f6; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; }
.badge-resolved { background:#22c55e; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; }
.badge-fp       { background:#6b7280; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; }
.badge-escalated { background:#a855f7; color:white; padding:2px 10px;
    border-radius:12px; font-size:0.78rem; }

/* Dataframe */
[data-testid="stDataFrame"] thead th {
    background-color: #1e2130 !important;
    color: #93c5fd !important;
}
</style>
""", unsafe_allow_html=True)

# ── Landing page ─────────────────────────────────────────────────────────────
st.markdown("# 🛡️ AML Fraud Detection Platform")
st.markdown("**Blockchain-Backed KYC & ML-Powered Fraud Intelligence**")
st.markdown("---")

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("""
    ### Navigate via the sidebar
    Use the pages listed in the left sidebar to explore each module of the platform.
    """)
with col2:
    st.markdown("""
    ### Architecture
    - **10 microservices** (Go + Python)
    - **Hyperledger Fabric** blockchain audit trail
    - **ML ensemble** (LGB · RF · XGB · GNN · Autoencoder)
    """)
with col3:
    st.markdown("""
    ### Pages
    - 📊 Overview & System Health
    - 👤 KYC Management
    - 🚨 Fraud Alerts
    - 📂 Case Management
    - 🤖 ML Intelligence
    - ⛓️ Blockchain Audit
    - 📈 Analytics
    """)

st.markdown("---")
st.markdown(
    "<small style='color:#6b7280'>Thesis project · Mayesha Marzia Zaman Mim · "
    "Hyperledger Fabric + ML Fraud Detection</small>",
    unsafe_allow_html=True,
)
