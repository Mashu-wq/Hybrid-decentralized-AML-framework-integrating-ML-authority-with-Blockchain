"""
Case Management — fully dynamic, no mock data.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import pandas as pd

from utils import api

st.set_page_config(page_title="Case Management", page_icon="📂", layout="wide")

PRIORITY_LABELS = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW",0:"UNSPECIFIED"}
PRIORITY_COLORS = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"}
STATUS_COLORS   = {
    "OPEN":"#3b82f6","IN_REVIEW":"#a855f7","PENDING_SAR":"#eab308",
    "CLOSED":"#22c55e","ESCALATED":"#f97316",
}

def _badge(text, color):
    return (f"<span style='background:{color};color:white;padding:2px 10px;"
            f"border-radius:12px;font-size:0.78rem;font-weight:600'>{text}</span>")

st.markdown("# 📂 Case Management")
st.markdown("---")

# ── KPIs ─────────────────────────────────────────────────────────────────────
stats, s_err = api.get_case_stats("7d")
if not stats:
    st.error(f"Case service unavailable: {s_err}. Start backend with `make run`.")
    st.stop()

k1,k2,k3,k4,k5 = st.columns(5)
k1.metric("Total Cases (7d)",   stats.get("TotalCases","—"))
k2.metric("Open",               stats.get("OpenCases","—"))
k3.metric("In Review",          stats.get("InReviewCases","—"))
k4.metric("SARs Generated",     stats.get("SARGenerated","—"))
k5.metric("Avg Resolution",     f"{stats.get('AvgResolutionHours',0):.1f} h")

st.markdown("---")

tab_list, tab_detail, tab_create, tab_analytics = st.tabs([
    "Case List","Case Detail","Create Case","Analytics"
])

# ── Tab 1 ─────────────────────────────────────────────────────────────────────
with tab_list:
    st.subheader("Investigation Cases")
    f1,f2,f3 = st.columns([2,2,1])
    with f1:
        status_f = st.selectbox("Status",
            ["All","OPEN","IN_REVIEW","PENDING_SAR","ESCALATED","CLOSED"])
    with f2:
        priority_f = st.selectbox("Priority",["All","CRITICAL","HIGH","MEDIUM","LOW"])
    with f3:
        limit_c = st.number_input("Limit",10,200,50,10)

    raw, err = api.get_cases(
        status=None if status_f=="All" else status_f, limit=int(limit_c)
    )
    if raw is None:
        st.error(f"Case service error: {err}. Start backend with `make run`.")
        cases = []
        total = 0
    elif isinstance(raw, dict):
        cases = raw.get("cases") or []
        total = raw.get("total", len(cases))
    else:
        cases = raw or []
        total = len(cases)

    if priority_f != "All":
        cases = [c for c in cases if PRIORITY_LABELS.get(c.get("priority",0)) == priority_f]

    if not cases:
        st.info("No cases match the current filters.")
    else:
        for c in cases:
            c["priority_label"] = PRIORITY_LABELS.get(c.get("priority",0),"—")
        df = pd.DataFrame(cases)
        show = [col for col in ["case_id","title","priority_label","status",
                                 "fraud_probability","sar_required","created_at"]
                if col in df.columns]
        df_show = df[show].copy()
        if "fraud_probability" in df_show.columns:
            df_show["fraud_probability"] = (df_show["fraud_probability"]*100).round(1).astype(str)+"%"
        df_show.columns = [c.replace("_"," ").title() for c in show]
        st.info(f"**{len(cases)}** of **{total}** cases")
        st.dataframe(df_show, use_container_width=True, height=440)
        st.download_button("Export CSV", df_show.to_csv(index=False),"cases.csv","text/csv")

# ── Tab 2 ─────────────────────────────────────────────────────────────────────
with tab_detail:
    st.subheader("Case Detail & Actions")
    cid_input = st.text_input("Case ID", placeholder="Paste case_id…")
    if st.button("Load Case", type="primary") and cid_input.strip():
        case_data, err2 = api.get_case(cid_input.strip())
        if case_data:
            st.session_state["current_case"] = case_data
        else:
            st.error(f"Case not found: {err2}")

    case = st.session_state.get("current_case")
    if case:
        col_info, col_action = st.columns([2,1])
        with col_info:
            prob  = case.get("fraud_probability",0)
            prio  = PRIORITY_LABELS.get(case.get("priority",0),"—")
            pcol  = PRIORITY_COLORS.get(prio,"#6b7280")
            st.markdown(f"### {case.get('title','Untitled')}")
            st.markdown(case.get("description",""))
            st.markdown(
                f"**Fraud Probability:** <span style='color:{pcol};font-size:1.3rem;"
                f"font-weight:700'>{prob*100:.1f}%</span>",
                unsafe_allow_html=True,
            )
            st.progress(prob)
            for k,v in {
                "Case ID":    case.get("case_id","—"),
                "Alert ID":   case.get("alert_id","—"),
                "Customer ID":case.get("customer_id","—"),
                "Status":     case.get("status","—"),
                "Priority":   prio,
                "SAR Required":"Yes" if case.get("sar_required") else "No",
                "Assignee":   case.get("assignee_id","Unassigned") or "Unassigned",
                "Created At": case.get("created_at","—"),
            }.items():
                c1,c2 = st.columns([1,2])
                c1.markdown(f"**{k}**")
                bc = PRIORITY_COLORS.get(v,"") if k=="Priority" else STATUS_COLORS.get(v,"") if k=="Status" else "#eab308" if k=="SAR Required" and v=="Yes" else ""
                c2.markdown(_badge(v,bc) if bc else str(v), unsafe_allow_html=bool(bc))

        with col_action:
            st.markdown("#### Actions")
            valid = {
                "OPEN":["IN_REVIEW","CLOSED","ESCALATED"],
                "IN_REVIEW":["PENDING_SAR","CLOSED","ESCALATED"],
                "PENDING_SAR":["CLOSED","IN_REVIEW"],
                "ESCALATED":["IN_REVIEW","CLOSED"],
                "CLOSED":["OPEN"],
            }
            with st.expander("Update Status", expanded=True):
                nxt = valid.get(case.get("status","OPEN"),["IN_REVIEW","CLOSED"])
                new_st = st.selectbox("Transition To", nxt)
                upd_by = st.text_input("Updated By", value="investigator-001")
                notes  = st.text_area("Notes")
                if st.button("Update", type="primary"):
                    res,e = api.update_case_status(case["case_id"],new_st,upd_by,notes)
                    if res:
                        st.success(f"→ {new_st}")
                        st.session_state.pop("current_case",None)
                    else:
                        st.error(f"Failed: {e}")

            with st.expander("Generate SAR"):
                st.warning("Triggers S3 upload and blockchain anchoring.")
                gen_by  = st.text_input("Generated By","investigator-001")
                sar_notes = st.text_area("SAR Notes")
                if st.button("Generate SAR", type="secondary"):
                    if not case.get("sar_required"):
                        st.warning("SAR not required for this case.")
                    elif case.get("sar_s3_key"):
                        st.warning("SAR already exists.")
                    else:
                        res,e = api.generate_sar(case["case_id"],gen_by,sar_notes)
                        st.success(f"SAR key: {res.get('s3_key', res.get('sar_s3_key','—'))}") if res else st.error(f"Failed: {e}")
    else:
        st.info("Enter a Case ID and click Load Case.")

# ── Tab 3 ─────────────────────────────────────────────────────────────────────
with tab_create:
    st.subheader("Create New Case")
    with st.form("create_form"):
        c1,c2 = st.columns(2)
        with c1:
            alert_id   = st.text_input("Alert ID *")
            customer_id = st.text_input("Customer ID *")
            tx_hash    = st.text_input("Transaction Hash")
        with c2:
            title    = st.text_input("Title *", value="Suspicious Transaction Pattern")
            priority = st.selectbox("Priority",["CRITICAL","HIGH","MEDIUM","LOW"])
            assignee = st.text_input("Assignee ID","investigator-001")
        description  = st.text_area("Description","Multiple high-value cross-border transfers detected.")
        fraud_prob   = st.slider("Fraud Probability",0.0,1.0,0.75,0.01)
        sar_required = st.checkbox("SAR Required", value=(fraud_prob>0.80))
        if st.form_submit_button("Create Case", type="primary"):
            if not all([alert_id,customer_id,title]):
                st.error("Alert ID, Customer ID, and Title are required.")
            else:
                res,e = api.create_case({
                    "alert_id":alert_id,"customer_id":customer_id,"tx_hash":tx_hash,
                    "title":title,"description":description,
                    "priority":{"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}[priority],
                    "assignee_id":assignee,"fraud_probability":fraud_prob,"sar_required":sar_required,
                })
                if res:
                    st.success(f"Case created: `{res.get('case_id',res.get('CaseID','—'))}`")
                else:
                    st.error(f"Failed: {e}")

# ── Tab 4 ─────────────────────────────────────────────────────────────────────
with tab_analytics:
    st.subheader("Case Analytics")
    col_l,col_r = st.columns(2)
    with col_l:
        fig1 = go.Figure(go.Pie(
            labels=["Open","In Review","Pending SAR","Closed"],
            values=[stats.get("OpenCases",0),stats.get("InReviewCases",0),
                    stats.get("PendingSARCases",0),stats.get("ClosedCases",0)],
            hole=0.5,marker_colors=["#3b82f6","#a855f7","#eab308","#22c55e"],
        ))
        fig1.update_layout(title="Status Distribution",
            template="plotly_dark",plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
            height=300,margin=dict(t=40,b=0,l=0,r=0))
        st.plotly_chart(fig1, use_container_width=True)
    with col_r:
        sar_rate = stats.get("SARGenerated",0)/max(stats.get("TotalCases",1),1)*100
        s1,s2,s3 = st.columns(3)
        s1.metric("SAR Rate",   f"{sar_rate:.1f}%")
        s2.metric("Avg Res.",   f"{stats.get('AvgResolutionHours',0):.1f} h")
        s3.metric("Critical",   stats.get("CriticalCases",0))
