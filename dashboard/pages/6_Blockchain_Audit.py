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
import hashlib
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
        st.caption(
            "Ledger height — the number of blocks on each channel. It increments "
            "with every committed transaction (register a customer, score a "
            "transaction, file a SAR…), and can only go up. Fire a transaction and "
            "refresh to watch it tick up live."
        )
    else:
        st.json(bc_health)
else:
    st.error(f"Blockchain service offline: {bc_err}. Start with `make fabric-up && make chaincode-deploy`.")
    st.stop()

st.markdown("---")

tab_process, tab_trail, tab_compliance, tab_integrity, tab_explorer = st.tabs([
    "🔗 Blockchain Process", "Audit Trail", "Compliance Report",
    "🔒 Receipt Integrity", "Architecture"
])

# ── Tab 0: Blockchain Process (end-to-end visualization) ──────────────────────
with tab_process:
    st.subheader("How a record becomes immutable — first to last")
    st.caption(
        "Follow one transaction from submission to a permanent, multi-org-signed "
        "block. This is the Hyperledger Fabric execute → order → validate flow."
    )

    # ① Transaction lifecycle (Graphviz flow) ----------------------------------
    st.markdown("#### ① Transaction Lifecycle")
    st.graphviz_chart(r'''
    digraph G {
      rankdir=LR; bgcolor="#0f1117"; pad=0.3; nodesep=0.35; ranksep=0.55;
      node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=11];
      edge [color="#9ca3af" penwidth=1.4];

      tx     [label="1. Transaction\ndemo-suspicious-001" fillcolor="#3b82f6" fontcolor=white];
      client [label="2. Blockchain Service\n(client SDK proposes)" fillcolor="#22c55e" fontcolor=white];
      subgraph cluster_e {
        label="3. Endorse: each org simulates + signs"; style="rounded,dashed";
        color="#3d4470"; fontcolor="#93c5fd"; fontname="Helvetica";
        o1 [label="Org1\nPrimaryBank" fillcolor="#1a1d27" fontcolor="#e0e0e0"];
        o2 [label="Org2\nRegulator"   fillcolor="#1a1d27" fontcolor="#e0e0e0"];
        o3 [label="Org3\nPartnerBank" fillcolor="#1a1d27" fontcolor="#e0e0e0"];
      }
      order  [label="4. Ordering Service\nRaft · 3 orderers\nbatch -> block" fillcolor="#a855f7" fontcolor=white];
      valid  [label="5. Validate\nMAJORITY >= 2 of 3\n+ conflict check" fillcolor="#f97316" fontcolor=white];
      commit [label="6. Commit\nappend block · height +1" fillcolor="#ef4444" fontcolor=white];

      tx -> client;
      client -> o1; client -> o2; client -> o3;
      o1 -> order; o2 -> order; o3 -> order;
      order -> valid -> commit;
    }
    ''')
    st.caption(
        "Nothing touches the ledger until step 6. Steps 3–5 are what make it "
        "trustworthy: several organizations independently sign, and a majority "
        "must agree before the block is committed."
    )

    # ② Multi-org MAJORITY simulator -------------------------------------------
    st.markdown("---")
    st.markdown("#### ② Multi-Org Trust — the MAJORITY rule (interactive)")
    st.caption(
        "Every block must be endorsed by a MAJORITY of organizations (≥ 2 of 3). "
        "Toggle which orgs sign and watch whether the block commits. No single "
        "party — not even the bank — can write to the ledger alone."
    )
    orgs = [("Org1 · PrimaryBank", "#3b82f6", True),
            ("Org2 · Regulator",   "#22c55e", True),
            ("Org3 · PartnerBank", "#a855f7", False)]
    o_cols = st.columns(3)
    signs = []
    for col, (name, c, default) in zip(o_cols, orgs):
        with col:
            st.markdown(
                f"<div style='text-align:center;font-weight:700;color:{c}'>{name}</div>"
                "<div style='text-align:center;font-size:1.4rem;margin:4px 0'>📒</div>"
                "<div style='text-align:center;color:#9ca3af;font-size:0.75rem'>"
                "holds a full copy of the ledger</div>",
                unsafe_allow_html=True,
            )
            signs.append(st.checkbox("signs this block", value=default, key=f"sign_{name}"))
    n_signed = sum(signs)
    if n_signed >= 2:
        st.success(f"✅ {n_signed} of 3 signed → MAJORITY met → block **COMMITTED** to all three ledgers.")
    else:
        st.error(f"⛔ {n_signed} of 3 signed → MAJORITY not met → block **REJECTED**; the transaction does not commit.")
    st.caption(
        "Because the **Regulator (Org2)** runs its own peer and holds an identical "
        "copy, it verifies every record independently — the bank cannot fabricate "
        "or delete history on its own."
    )

    # ③ Immutable chain + tamper demo (live heights) ---------------------------
    st.markdown("---")
    st.markdown("#### ③ The Immutable Chain (live block heights)")

    def _heights(d):
        out = {}
        for ch, val in (d or {}).items():
            s = str(val)
            part = s.split("block_height=")[-1] if "block_height=" in s else ""
            try:
                out[ch] = int(part)
            except ValueError:
                out[ch] = None
        return out

    heights = _heights(details)
    ch_list = [c for c in heights if heights[c]] or ["audit-channel"]
    sel_ch = st.selectbox("Channel", ch_list, index=0)
    H = heights.get(sel_ch) or 3
    st.caption(
        f"`{sel_ch}` is currently at **block #{H}**. Each block stores the hash of "
        "the previous one — change any block and every later hash breaks."
    )

    def _hash(n):
        return hashlib.sha256(f"{sel_ch}-block-{n}".encode()).hexdigest()[:12]

    tampered = max(H - 2, 0)
    do_tamper = st.checkbox(f"🔓 Simulate tampering with an old block (edit Block #{tampered})")

    blocks = [b for b in (H - 2, H - 1, H) if b >= 0]
    cards = []
    for i, n in enumerate(blocks):
        broken = do_tamper and n >= tampered
        border = "#ef4444" if broken else "#22c55e"
        status = "✗ HASH MISMATCH" if broken else "✓ valid"
        prev = "genesis" if n == 0 else _hash(n - 1)
        datah = _hash(n) + ("  (edited!)" if do_tamper and n == tampered else "")
        cards.append(
            "<div style='display:inline-block;vertical-align:top;background:#1a1d27;"
            f"border:2px solid {border};border-radius:8px;padding:10px 12px;width:210px'>"
            f"<div style='font-weight:700;color:#e0e0e0'>Block #{n}</div>"
            f"<div style='color:#9ca3af;font-size:0.72rem;margin-top:6px'>dataHash<br>"
            f"<code style='color:#bfdbfe'>{datah}</code></div>"
            f"<div style='color:#9ca3af;font-size:0.72rem;margin-top:4px'>prevHash<br>"
            f"<code style='color:#bfdbfe'>{prev}</code></div>"
            f"<div style='margin-top:6px;color:{border};font-weight:600;font-size:0.8rem'>{status}</div>"
            "</div>"
        )
    arrow = "<span style='font-size:1.5rem;color:#9ca3af;margin:0 6px'>→</span>"
    st.markdown(
        "<div style='white-space:nowrap;overflow-x:auto;padding:4px 0'>"
        + arrow.join(cards) + "</div>",
        unsafe_allow_html=True,
    )
    if do_tamper:
        st.error(
            "Editing an old block changes its hash, so the next block's prevHash no "
            "longer matches — every block after it becomes invalid and the peers "
            "reject the ledger. **That is why the chain is tamper-evident.**"
        )
    else:
        st.info(
            "Each block's prevHash equals the previous block's dataHash, forming an "
            "unbroken chain back to the genesis block (#0)."
        )
    st.caption(
        "Hashes shown are illustrative (real Fabric hashes are 64-hex SHA-256). "
        "Block heights are live from the network — fire a transaction and refresh "
        "to watch the height increment."
    )

# ── Tab 1: Audit Trail ────────────────────────────────────────────────────────
with tab_trail:
    st.subheader("Entity Audit Trail Query")
    st.markdown(
        "Look up the immutable event history on the **audit-channel** for a "
        "**transaction** (by tx hash) or a **case** (by case ID)."
    )

    c1, c2 = st.columns(2)
    with c1:
        entity_id = st.text_input("Entity ID",
            placeholder="Transaction hash (e.g. demo-suspicious-001) / Case ID…")
    with c2:
        # Only TRANSACTION and CASE entities are written to the audit-channel.
        # Alerts live on the alert-channel, KYC on the kyc-channel — querying
        # those here would always return empty, so they are not offered.
        entity_type = st.selectbox("Entity Type", ["TRANSACTION", "CASE"])

    if st.button("Query Audit Trail", type="primary") and entity_id.strip():
        trail_data, trail_err = api.get_audit_trail(entity_id.strip(), entity_type)

        # A real failure has a non-None error (e.g. connection refused). An empty
        # list is a SUCCESSFUL query that simply found no records — it must NOT be
        # reported as "service unavailable".
        if trail_err:
            st.error(
                f"Blockchain service error: {trail_err}. "
                "Start with `make fabric-up` then `make chaincode-deploy`."
            )
            st.stop()

        if isinstance(trail_data, dict):
            events = trail_data.get("events") or trail_data.get("payload") or []
        else:
            events = trail_data or []

        if not events:
            st.info(
                f"No on-chain audit records found for `{entity_id.strip()}` as "
                f"**{entity_type}**.\n\n"
                "The **audit-channel** stores TRANSACTION receipts and CASE events "
                "(investigator actions, SAR filings). Check the ID matches the type:\n\n"
                "- **TRANSACTION** → a transaction hash (e.g. `demo-suspicious-001`)\n"
                "- **CASE** → a case ID (e.g. `case-…`)\n\n"
                "Alerts are anchored on the separate *alert-channel*, not the audit "
                "trail, so an alert or customer ID returns nothing here."
            )
        else:
            st.success(f"Found **{len(events)}** on-chain events for `{entity_id.strip()}`")

            # Timeline chart — audit records use: recordType, createdAt, actorID,
            # entityType, entityID, txId, hash (Fabric audit-channel record shape).
            df_ev = pd.DataFrame(events)
            if "createdAt" in df_ev.columns and "recordType" in df_ev.columns:
                df_ev["ts"] = pd.to_datetime(df_ev["createdAt"])
                df_ev["y"]  = 1

                fig_tl = px.scatter(
                    df_ev, x="ts", y="y",
                    color="recordType",
                    color_discrete_map=EVENT_COLORS,
                    hover_data=[c for c in ["recordType","entityType","actorID"] if c in df_ev.columns],
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
                ev_type = ev.get("recordType", "—")
                color   = EVENT_COLORS.get(ev_type, "#6b7280")
                st.markdown(
                    f"<div style='background:#1a1d27;border-left:4px solid {color};"
                    f"border-radius:6px;padding:12px 16px;margin-bottom:8px'>"
                    f"<div style='display:flex;justify-content:space-between'>"
                    f"<span style='color:{color};font-weight:700;font-size:0.9rem'>{ev_type}</span>"
                    f"<span style='color:#9ca3af;font-size:0.8rem'>"
                    f"{ev.get('createdAt','—')}</span></div>"
                    f"<div style='color:#d1d5db;font-size:0.82rem;margin-top:6px'>"
                    f"Entity: <b>{ev.get('entityType','—')}</b> · "
                    f"ID: <b>{ev.get('entityID','—')}</b> · "
                    f"Actor: <b>{ev.get('actorID','—')}</b></div>"
                    f"<div style='color:#6b7280;font-size:0.75rem;margin-top:4px'>"
                    f"Fabric TX: {ev.get('txId','—')} · "
                    f"Hash: {ev.get('hash','—')}</div>"
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

        # KPIs — audit-channel compliance payload:
        # totalEvents, transactionsProcessed, sarsFiled, investigatorActions,
        # modelPredictions, byEntityType, sampleRecords.
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Events",          f"{report.get('totalEvents',0):,}")
        k2.metric("Transactions Processed",f"{report.get('transactionsProcessed',0):,}")
        k3.metric("SARs Filed",            report.get("sarsFiled",0))
        k4.metric("Investigator Actions",  report.get("investigatorActions",0))
        k5.metric("Model Predictions",     report.get("modelPredictions",0))

        st.caption(
            f"Window: {report.get('startDate','—')} → {report.get('endDate','—')} · "
            "Pulled from the audit-channel ledger (regulator-verifiable)."
        )

        # Entity-type breakdown
        st.markdown("---")
        st.markdown("#### Records by Entity Type")
        by_entity = report.get("byEntityType", {}) or {}
        if by_entity:
            ent_df = pd.DataFrame(
                [{"Entity Type": k, "Count": v} for k, v in by_entity.items()]
            )
            st.dataframe(ent_df, use_container_width=True, hide_index=True)

        # Audit funnel chart (from on-chain receipts)
        st.markdown("---")
        st.markdown("#### Audit Funnel")
        funnel_vals = [
            report.get("totalEvents", 0),
            report.get("transactionsProcessed", 0),
            report.get("investigatorActions", 0),
            report.get("sarsFiled", 0),
        ]
        funnel_labels = [
            "Total Audit Events",
            "Transactions Processed",
            "Investigator Actions",
            "SARs Filed",
        ]
        fig_f = go.Figure(go.Funnel(
            y=funnel_labels,
            x=funnel_vals,
            textinfo="value+percent initial",
            marker_color=["#3b82f6","#f97316","#eab308","#a855f7"],
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

# ── Tab 3: Receipt Integrity (completeness + privacy) ─────────────────────────
with tab_integrity:
    st.subheader("Gap-Free Receipt Sequence — Audit Completeness")
    st.markdown(
        "Every ML-scored transaction is anchored with a **chaincode-assigned, "
        "per-organization sequence number** (always last + 1). The on-chain series "
        "is gap-free *by construction*, so the latest sequence equals the exact "
        "number of receipts the bank has ever anchored. A regulator reconciles it "
        "against the bank's independently reported transaction volume — any "
        "shortfall is **provable evidence of omitted transactions**, and "
        "backfilling is visible as a skew between sequence order and the "
        "`processedAt` timestamps."
    )

    seq_data, seq_err = api.get_audit_sequence_status()
    if seq_err:
        st.error(f"Blockchain service error: {seq_err}")
    elif not seq_data:
        st.info(
            "No receipts anchored yet — the sequence counters appear after the "
            "first transaction is scored (see `docs/dashboard_test_steps.txt`)."
        )
    else:
        cols = st.columns(max(len(seq_data), 1))
        for col, s in zip(cols, seq_data):
            col.metric(f"{s.get('mspId', '—')} receipts", f"{s.get('latestSequence', 0):,}")
        st.caption(
            "Latest receipt sequence per organization. Receipts 1…N all exist on "
            "the ledger — the chaincode rejects anything else."
        )

        st.markdown("##### Reconcile against the bank's processed-transaction count")
        st.caption(
            "In production this number comes from an independent source (the "
            "bank's core system count, or the regulator's reported-volume figure) "
            "— never from the chain itself."
        )
        c1, c2 = st.columns([1, 2])
        with c1:
            expected = st.number_input("Expected transaction count", min_value=0, value=0, step=1)
        if st.button("Check Completeness", type="primary"):
            comp, comp_err = api.get_audit_completeness(expected)
            if comp_err or not comp:
                st.error(f"Completeness check failed: {comp_err}")
            else:
                k1, k2, k3 = st.columns(3)
                k1.metric("Anchored receipts", f"{comp.get('anchored_receipts', 0):,}")
                k2.metric("Expected", f"{comp.get('expected_count', 0):,}")
                k3.metric("Missing", f"{comp.get('missing_receipts', 0):,}")
                if comp.get("complete"):
                    st.success(
                        f"✓ Complete — every processed transaction has an on-chain "
                        f"receipt ({comp.get('msp_id', '')})."
                    )
                else:
                    st.error(
                        f"✗ {comp.get('missing_receipts', 0)} transaction(s) were "
                        "processed but never anchored — a provable audit omission."
                    )

    st.markdown("---")
    st.subheader("Private Receipt Details — What Each Org Can See")
    st.markdown(
        "The shared ledger record carries only **fraud metadata + a SHA-256 digest** "
        "of the business details. The details themselves (customer pseudonym, "
        "amount, corridor) live in a **Private Data Collection** shared by the "
        "issuing bank and the regulator only — the partner bank stores just the "
        "hash. Customer IDs are **HMAC-pseudonymized** before they ever leave the "
        "bank, so no raw identifier reaches any channel."
    )

    detail_id = st.text_input(
        "Receipt record ID (= transaction hash)",
        placeholder="e.g. demo-suspicious-001",
        key="receipt_details_id",
    )
    if st.button("Fetch Private Details") and detail_id.strip():
        details, det_err = api.get_receipt_details_on_chain(detail_id.strip())
        if det_err or not details:
            st.error(
                f"Lookup failed: {det_err}. Either the receipt does not exist, or "
                "this peer's org is not a member of the private collection "
                "(which is exactly the point — Org3/PartnerBank gets this error)."
            )
        else:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Private details** (bank + regulator only)")
                st.json(details.get("details", {}))
            with c2:
                st.markdown("**Integrity check** (against the public record)")
                if details.get("verified"):
                    st.success("✓ SHA-256(private details) matches the on-chain detailsHash")
                else:
                    st.error("✗ Hash mismatch — private data was tampered with")
                st.caption(f"detailsHash: `{details.get('detailsHash', '—')}`")
