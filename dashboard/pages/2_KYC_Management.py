"""
KYC Management Page
Browse customers, update KYC/risk status, register new customers,
and cross-verify identity records against the Hyperledger Fabric ledger.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd
from datetime import datetime

from utils import api

st.set_page_config(page_title="KYC Management", page_icon="👤", layout="wide")

# ── CSS helpers ───────────────────────────────────────────────────────────────
RISK_COLORS = {
    "LOW":      "#22c55e",
    "MEDIUM":   "#eab308",
    "HIGH":     "#f97316",
    "CRITICAL": "#ef4444",
}
STATUS_COLORS = {
    "APPROVED":     "#22c55e",
    "PENDING":      "#3b82f6",
    "UNDER_REVIEW": "#a855f7",
    "REJECTED":     "#ef4444",
    "EXPIRED":      "#6b7280",
}

def _badge(text: str, color: str) -> str:
    return (
        f"<span style='background:{color};color:white;padding:2px 10px;"
        f"border-radius:12px;font-size:0.78rem;font-weight:600'>{text}</span>"
    )

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# 👤 KYC Management")
st.markdown("Customer identity verification, risk classification, and blockchain audit.")
st.markdown("---")

# ── Tabs ─────────────────────────────────────────────────────────────────────
tab_list, tab_detail, tab_register, tab_chain = st.tabs([
    "Customer List", "Customer Detail", "Register Customer", "Blockchain Verification"
])

# ── Tab 1: Customer List ─────────────────────────────────────────────────────
with tab_list:
    st.subheader("Customer Registry")

    col_f1, col_f2, col_f3 = st.columns([2, 2, 1])
    with col_f1:
        status_filter = st.selectbox(
            "KYC Status",
            ["All", "PENDING", "APPROVED", "UNDER_REVIEW", "REJECTED", "EXPIRED"],
        )
    with col_f2:
        risk_filter = st.selectbox(
            "Risk Level", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        )
    with col_f3:
        limit = st.number_input("Limit", min_value=10, max_value=200, value=50, step=10)

    data, err = api.get_customers(
        status=None if status_filter == "All" else status_filter,
        limit=int(limit),
    )

    if not data:
        st.error(f"KYC service unavailable: {err}. Start with `make run`.")
        customers = []
    else:
        customers = data.get("customers", [])

    # Apply risk filter client-side
    if risk_filter != "All":
        customers = [c for c in customers if c.get("risk_level") == risk_filter]

    if not customers:
        st.warning("No customers match the selected filters.")
    else:
        df = pd.DataFrame(customers)
        display_cols = [c for c in
            ["full_name", "email", "country_code", "kyc_status",
             "risk_level", "source_of_funds", "created_at"]
            if c in df.columns]
        df_show = df[display_cols].copy()
        df_show.columns = [c.replace("_", " ").title() for c in display_cols]

        # Summary metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Shown",   len(customers))
        m2.metric("Approved",      sum(1 for c in customers if c.get("kyc_status") == "APPROVED"))
        m3.metric("Pending Review",sum(1 for c in customers if c.get("kyc_status") in ("PENDING","UNDER_REVIEW")))
        m4.metric("High/Critical", sum(1 for c in customers if c.get("risk_level") in ("HIGH","CRITICAL")))

        st.dataframe(df_show, use_container_width=True, height=420)

        csv = df_show.to_csv(index=False)
        st.download_button("Export CSV", csv, "kyc_customers.csv", "text/csv")

# ── Tab 2: Customer Detail ────────────────────────────────────────────────────
with tab_detail:
    st.subheader("Customer Detail Lookup")
    customer_id_input = st.text_input("Customer ID (UUID)", placeholder="e.g. 550e8400-e29b-41d4-…")

    if st.button("Fetch Customer", type="primary") and customer_id_input.strip():
        cid = customer_id_input.strip()
        cust, err = api.get_customer(cid)
        if not cust:
            st.error(f"Customer not found: {err}")
        else:
            st.session_state["kyc_cust"] = cust
            st.session_state["kyc_cid"]  = cid
            # Fetch decrypted PII separately (stored encrypted in Vault)
            pii, _ = api.get_customer_pii(cid)
            st.session_state["kyc_pii"] = pii or {}

    cust = st.session_state.get("kyc_cust")
    cid  = st.session_state.get("kyc_cid", "")
    pii  = st.session_state.get("kyc_pii", {})

    if cust:
        col_info, col_action = st.columns([2, 1])
        with col_info:
            full_name = pii.get("full_name") or cust.get("full_name", "N/A")
            st.markdown(f"### {full_name}")
            info_rows = {
                "Customer ID":    cust.get("id", cid),
                "Full Name":      pii.get("full_name", "—"),
                "Email":          pii.get("email", "—"),
                "Phone":          pii.get("phone_number", "—"),
                "Date of Birth":  pii.get("date_of_birth", "—"),
                "Address":        pii.get("address_line1", "—"),
                "Country":        cust.get("country_code", "—"),
                "City":           cust.get("city", "—"),
                "Nationality":    cust.get("nationality", "—"),
                "KYC Status":     cust.get("kyc_status", "—"),
                "Risk Level":     cust.get("risk_level", "—"),
                "Document Type":  cust.get("document_type", "—"),
                "Source of Funds":cust.get("source_of_funds", "—"),
                "Occupation":     cust.get("occupation", "—"),
                "Employer":       cust.get("employer", "—"),
                "Monthly Volume": f"${cust.get('expected_monthly_volume', 0):,.2f}",
                "Created At":     cust.get("created_at", "—"),
                "Identity Hash":  cust.get("identity_hash", "—"),
                "Blockchain TxID":cust.get("blockchain_tx_id", "—"),
            }
            for k, v in info_rows.items():
                risk_col = RISK_COLORS.get(v, "") if k == "Risk Level" else ""
                stat_col = STATUS_COLORS.get(v, "") if k == "KYC Status" else ""
                badge_html = ""
                if risk_col:
                    badge_html = _badge(v, risk_col)
                elif stat_col:
                    badge_html = _badge(v, stat_col)

                col_k, col_v = st.columns([1, 2])
                col_k.markdown(f"**{k}**")
                if badge_html:
                    col_v.markdown(badge_html, unsafe_allow_html=True)
                else:
                    col_v.markdown(str(v))

        with col_action:
            st.markdown("#### Update KYC Status")
            new_status = st.selectbox("New Status",
                ["APPROVED", "REJECTED", "UNDER_REVIEW", "EXPIRED"])
            new_risk   = st.selectbox("Risk Level",
                ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            verifier   = st.text_input("Verifier ID", value="analyst-001")
            reason     = st.text_area("Reason", placeholder="Reason for status change…")
            if st.button("Update Status", type="primary"):
                result, err2 = api.update_kyc_status(cid, new_status, new_risk, verifier, reason)
                if result:
                    st.success(
                        f"Status updated → **{result.get('kyc_status', new_status)}** | "
                        f"Risk: **{result.get('risk_level', new_risk)}**"
                    )
                    refreshed, _ = api.get_customer(cid)
                    if refreshed:
                        st.session_state["kyc_cust"] = refreshed
                    refreshed_pii, _ = api.get_customer_pii(cid)
                    if refreshed_pii:
                        st.session_state["kyc_pii"] = refreshed_pii
                    st.rerun()
                else:
                    st.error(f"Update failed: {err2}")

        # Alerts for this customer
        st.markdown("---")
        st.markdown("#### Fraud Alerts for this Customer")
        alerts_data, _ = api.get_alerts_for_customer(cid)
        if alerts_data and "alerts" in alerts_data:
            alert_list = alerts_data["alerts"]
        else:
            alert_list = []
        if alert_list:
            st.dataframe(pd.DataFrame(alert_list)[[
                "alert_id","fraud_probability","risk_level","status","created_at"
            ]], use_container_width=True)
        else:
            st.info("No alerts found for this customer.")

# ── Tab 3: Register Customer ──────────────────────────────────────────────────
with tab_register:
    st.subheader("Register New Customer")
    st.markdown("Submit a new KYC registration. PII is encrypted via Vault (AES-256-GCM) before storage.")

    with st.form("register_form"):
        c1, c2 = st.columns(2)
        with c1:
            full_name    = st.text_input("Full Name *")
            email        = st.text_input("Email *")
            phone        = st.text_input("Phone Number")
            dob          = st.text_input("Date of Birth (YYYY-MM-DD)")
            doc_type     = st.selectbox("Document Type *",
                ["PASSPORT", "NATIONAL_ID", "DRIVING_LICENSE"])
            doc_number   = st.text_input("Document Number")
            doc_expiry   = st.text_input("Expiry Date (YYYY-MM-DD)")
            country_issue = st.text_input("Country of Issue (ISO2)", value="US")
        with c2:
            nationality  = st.text_input("Nationality")
            country_code = st.text_input("Residence Country (ISO2) *", value="US")
            city         = st.text_input("City")
            postal       = st.text_input("Postal Code")
            occupation   = st.text_input("Occupation")
            employer     = st.text_input("Employer")
            source_funds = st.selectbox("Source of Funds",
                ["Employment", "Business", "Investment", "Savings", "Inheritance", "Other"])
            monthly_vol  = st.number_input("Expected Monthly Volume (USD)", min_value=0.0,
                                           value=5000.0, step=500.0)

        addr1 = st.text_input("Address Line 1")
        addr2 = st.text_input("Address Line 2")

        submitted = st.form_submit_button("Register Customer", type="primary")
        if submitted:
            if not all([full_name, email, doc_type, country_code]):
                st.error("Full name, email, document type and country code are required.")
            else:
                body = {
                    "full_name": full_name, "email": email, "phone_number": phone,
                    "date_of_birth": dob, "document_type": doc_type,
                    "document_number": doc_number, "expiry_date": doc_expiry,
                    "country_of_issue": country_issue, "nationality": nationality,
                    "country_code": country_code, "city": city, "postal_code": postal,
                    "address_line1": addr1, "address_line2": addr2,
                    "occupation": occupation, "employer": employer,
                    "source_of_funds": source_funds,
                    "expected_monthly_volume": monthly_vol,
                }
                result, err2 = api.register_customer(body)
                if result:
                    st.success(f"Customer registered! ID: `{result.get('customer_id','—')}`  "
                               f"| Identity hash: `{result.get('identity_hash','—')}`")
                else:
                    st.error(f"Registration failed: {err2}")

# ── Tab 4: Blockchain Verification ────────────────────────────────────────────
with tab_chain:
    st.subheader("Blockchain KYC Verification")
    st.markdown(
        "Query the **Hyperledger Fabric kyc-channel** directly to verify identity "
        "records are immutably anchored on-chain."
    )

    bcid = st.text_input("Customer ID for blockchain lookup",
                          placeholder="e.g. 550e8400-e29b-41d4-…", key="bc_cid")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        fetch_record = st.button("Fetch On-Chain Record", type="primary")
    with col_btn2:
        fetch_history = st.button("Fetch Change History")

    if fetch_record and bcid.strip():
        record, err = api.get_kyc_on_chain(bcid.strip())
        if record:
            st.success("On-chain record found ✓")
            st.json(record)
        else:
            st.error(f"Blockchain lookup failed: {err}")

    if fetch_history and bcid.strip():
        history, err = api.get_kyc_history_on_chain(bcid.strip())
        if history:
            st.success("History retrieved ✓")
            st.json(history)
        else:
            st.error(f"History unavailable: {err}")
