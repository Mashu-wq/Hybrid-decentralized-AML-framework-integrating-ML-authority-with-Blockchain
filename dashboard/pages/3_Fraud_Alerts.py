"""
Fraud Alerts — fully dynamic, no mock data.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import json

from utils import api
from utils.risk import risk_level_from_score

st.set_page_config(page_title="Fraud Alerts", page_icon="🚨", layout="wide")

PRIORITY_MAP = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNSPECIFIED"}
RISK_COLORS  = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"}
STATUS_COLORS = {
    "OPEN":"#3b82f6","INVESTIGATING":"#a855f7","RESOLVED":"#22c55e",
    "FALSE_POSITIVE":"#6b7280","ESCALATED":"#f97316",
}

def _badge(text, color):
    return (f"<span style='background:{color};color:white;padding:2px 10px;"
            f"border-radius:12px;font-size:0.78rem;font-weight:600'>{text}</span>")

st.markdown("# 🚨 Fraud Alert Center")
st.markdown("---")

# ── KPI stats ─────────────────────────────────────────────────────────────────
period_opts = {"Last 24 h":"24h","Last 7 days":"7d","Last 30 days":"30d"}
period_sel  = st.selectbox("Stats Period", list(period_opts.keys()), key="al_period")
period      = period_opts[period_sel]

stats, s_err = api.get_alert_stats(period)
if not stats:
    st.error(f"Alert service unavailable: {s_err}. Start backend with `make run`.")
    st.stop()

s1,s2,s3,s4,s5,s6,s7 = st.columns(7)
s1.metric("Total",          stats.get("TotalAlerts","—"))
s2.metric("Open",           stats.get("OpenAlerts","—"))
s3.metric("Critical",       stats.get("CriticalAlerts","—"))
s4.metric("High",           stats.get("HighAlerts","—"))
s5.metric("Resolved",       stats.get("ResolvedAlerts","—"))
s6.metric("False Positives",stats.get("FalsePositives","—"))
s7.metric("Escalated",      stats.get("EscalatedAlerts","—"))

st.markdown("---")

tab_list, tab_detail, tab_charts = st.tabs(["Alert List","Alert Detail & Actions","Analytics"])

# ── Tab 1: Alert List ─────────────────────────────────────────────────────────
with tab_list:
    st.subheader("Active Alerts")
    f1,f2,f3,f4 = st.columns([2,2,1,1])
    with f1:
        status_f = st.selectbox("Status",
            ["All","OPEN","INVESTIGATING","ESCALATED","RESOLVED","FALSE_POSITIVE"])
    with f2:
        min_prob = st.slider("Min Fraud Probability", 0.0, 1.0, 0.0, 0.05)
    with f3:
        lim = st.number_input("Limit", 10, 200, 50, 10)
    with f4:
        sort_by = st.selectbox("Sort By",["fraud_probability","created_at","risk_score"])

    raw, err = api.get_alerts(
        status=None if status_f=="All" else status_f,
        min_fraud_prob=min_prob if min_prob>0 else None,
        limit=int(lim),
    )
    if raw is None:
        st.error(f"Alert service error: {err}. Start backend with `make run`.")
        alerts = []
        total  = 0
    elif isinstance(raw, dict):
        alerts = raw.get("alerts") or []
        total  = raw.get("total", len(alerts))
    else:
        alerts = raw or []
        total  = len(alerts)

    if alerts:
        alerts.sort(key=lambda a: a.get(sort_by, 0), reverse=True)

    if not alerts:
        st.info("No alerts match the current filters.")
    else:
        st.session_state["alert_list"] = alerts
        df = pd.DataFrame(alerts)
        # Risk level is driven by the composite risk_score (matches on-chain),
        # falling back to the ML-probability-derived priority if score is absent.
        def _row_risk_level(row):
            lvl = risk_level_from_score(row.get("risk_score"))
            return lvl if lvl else PRIORITY_MAP.get(row.get("priority", 0), "—")
        df["risk_level"] = df.apply(_row_risk_level, axis=1)
        df["fraud_pct"] = (df["fraud_probability"]*100).round(1).astype(str)+"%"
        display = [c for c in ["alert_id","customer_id","fraud_pct","risk_level",
                                "status","model_version","created_at"] if c in df.columns]
        df_show = df[display].copy()
        df_show.columns = [c.replace("_"," ").replace("fraud pct","Fraud %").title() for c in display]
        st.info(f"**{len(alerts)}** of **{total}** alerts")
        st.dataframe(df_show, use_container_width=True, height=440)
        st.download_button("Export CSV", df_show.to_csv(index=False), "alerts.csv","text/csv")

# ── Tab 2: Alert Detail ───────────────────────────────────────────────────────
with tab_detail:
    st.subheader("Alert Detail & Triage")
    aid_input = st.text_input("Alert ID", placeholder="Paste alert_id from list…")

    if st.button("Load Alert", type="primary") and aid_input.strip():
        alert, err2 = api.get_alert(aid_input.strip())
        if alert:
            st.session_state["current_alert"] = alert
        else:
            st.error(f"Alert not found: {err2}")

    alert = st.session_state.get("current_alert")
    if alert:
        col_a, col_b = st.columns([2,1])
        with col_a:
            prob  = alert.get("fraud_probability", 0)
            rl    = (risk_level_from_score(alert.get("risk_score"))
                     or alert.get("risk_level")
                     or PRIORITY_MAP.get(alert.get("priority",0),"—"))
            color = RISK_COLORS.get(rl, "#6b7280")
            try:
                score_val = float(alert.get("risk_score"))
            except (TypeError, ValueError):
                score_val = prob*100
            st.markdown(f"#### Alert `{alert['alert_id']}`")

            # Two clearly-separated numbers so they are never conflated: the
            # COMPOSITE risk score drives the decision; the ML probability is a
            # minor (10%) input that stays low by design on bank-wire features.
            m1, m2 = st.columns(2)
            m1.metric("Composite Risk Score", f"{score_val:.1f} / 100", rl)
            m2.metric("ML Fraud Probability", f"{prob*100:.1f}%",
                      "minor input · 10% weight", delta_color="off")
            st.caption(
                "The **composite risk score** sets the alert level "
                "(CRITICAL > 85 · HIGH ≥ 70 · MEDIUM ≥ 50). It blends the ML fraud "
                "probability (weighted only 10%) with FATF rule signals — KYC risk "
                "tier, merchant category and jurisdiction risk. On adapted bank-wire "
                "features the ML probability stays low by design, so a small % "
                "alongside a high composite score is expected."
            )

            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score_val,
                title={"text":"Composite Risk Score (0–100)",
                       "font":{"size":13,"color":"#9ca3af"}},
                number={"font":{"color":color,"size":32}},
                gauge={
                    "axis":{"range":[0,100]},
                    "bar":{"color":color},
                    "steps":[
                        {"range":[0,50],"color":"#1e2130"},
                        {"range":[50,70],"color":"#2d3150"},
                        {"range":[70,85],"color":"#3d2020"},
                        {"range":[85,100],"color":"#4d1010"},
                    ],
                    "threshold":{"line":{"color":"white","width":3},"value":score_val},
                },
            ))
            fig_g.update_layout(height=240,
                template="plotly_dark",plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
                margin=dict(t=40,b=10,l=10,r=10))
            st.plotly_chart(fig_g, use_container_width=True)

            for k,v in {
                "Status":     alert.get("status","—"),
                "Customer ID":alert.get("customer_id","—"),
                "Tx Hash":    alert.get("tx_hash","—"),
                "Risk Level": rl,
                "Model":      alert.get("model_version","—"),
                "Assignee":   alert.get("assignee_id","Unassigned") or "Unassigned",
                "Created At": alert.get("created_at","—"),
            }.items():
                c1,c2 = st.columns([1,2])
                c1.markdown(f"**{k}**")
                bc = STATUS_COLORS.get(v,"") if k=="Status" else RISK_COLORS.get(v,"") if k=="Risk Level" else ""
                if bc:
                    c2.markdown(_badge(v,bc), unsafe_allow_html=True)
                else:
                    c2.markdown(str(v))

            shap_raw = alert.get("shap_explanation_json","")
            if shap_raw:
                try:
                    shap_data = json.loads(shap_raw) if isinstance(shap_raw,str) else shap_raw
                    if isinstance(shap_data,list):
                        df_s = pd.DataFrame(shap_data)
                        shap_col = "SHAPValue" if "SHAPValue" in df_s.columns else "shap_value"
                        feat_col = "FeatureName" if "FeatureName" in df_s.columns else "feature_name"
                        if shap_col in df_s.columns and feat_col in df_s.columns:
                            df_s = df_s.sort_values(shap_col,key=abs,ascending=True).head(12)
                            fig_s = px.bar(df_s, x=shap_col, y=feat_col, orientation="h",
                                color=shap_col,
                                color_continuous_scale=["#22c55e","#f9fafb","#ef4444"],
                                color_continuous_midpoint=0)
                            fig_s.update_layout(template="plotly_dark",
                                plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
                                height=300,margin=dict(t=0,b=0,l=0,r=0),
                                showlegend=False,coloraxis_showscale=False)
                            st.markdown("#### SHAP Contributions")
                            st.plotly_chart(fig_s, use_container_width=True)
                except Exception:
                    pass

        with col_b:
            st.markdown("#### Triage Actions")
            with st.expander("Update Status", expanded=True):
                new_st  = st.selectbox("New Status",
                    ["INVESTIGATING","RESOLVED","FALSE_POSITIVE","ESCALATED"])
                by_user = st.text_input("Changed By", value="analyst-001")
                notes   = st.text_area("Notes")
                if st.button("Submit", type="primary"):
                    res, e = api.update_alert_status(alert["alert_id"],new_st,by_user,notes)
                    if res:
                        st.success(f"Updated → {new_st}")
                        st.session_state.pop("current_alert",None)
                    else:
                        st.error(f"Failed: {e}")

            with st.expander("Assign Alert"):
                assignee = st.text_input("Assignee ID", value="analyst-002")
                if st.button("Assign"):
                    res,e = api.assign_alert(alert["alert_id"],assignee)
                    st.success("Assigned") if res else st.error(f"Failed: {e}")

            with st.expander("Escalate Alert"):
                analyst = st.text_input("Analyst ID", value="senior-001")
                reason  = st.text_area("Reason")
                if st.button("Escalate", type="secondary"):
                    res,e = api.escalate_alert(alert["alert_id"],analyst,reason)
                    st.success("Escalated") if res else st.error(f"Failed: {e}")
    else:
        st.info("Enter an Alert ID above and click Load Alert.")

# ── Tab 3: Analytics Charts ───────────────────────────────────────────────────
with tab_charts:
    st.subheader("Alert Analytics")
    col_l, col_r = st.columns(2)

    with col_l:
        prios = {
            "CRITICAL": stats.get("CriticalAlerts",0),
            "HIGH":     stats.get("HighAlerts",0),
            "MEDIUM":   stats.get("MediumAlerts",0),
            "LOW":      stats.get("LowAlerts",0),
        }
        fig_p = go.Figure(go.Bar(
            x=list(prios.keys()), y=list(prios.values()),
            marker_color=["#ef4444","#f97316","#eab308","#22c55e"],
            text=list(prios.values()), textposition="outside",
        ))
        fig_p.update_layout(title="Alerts by Priority",
            template="plotly_dark",plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
            height=300,margin=dict(t=40,b=0,l=0,r=0),showlegend=False)
        st.plotly_chart(fig_p, use_container_width=True)

    with col_r:
        status_dist = {
            "Open":          stats.get("OpenAlerts",0),
            "Resolved":      stats.get("ResolvedAlerts",0),
            "False Positive":stats.get("FalsePositives",0),
            "Escalated":     stats.get("EscalatedAlerts",0),
        }
        fig_s = go.Figure(go.Pie(
            labels=list(status_dist.keys()),values=list(status_dist.values()),hole=0.5,
            marker_colors=["#3b82f6","#22c55e","#6b7280","#f97316"],
        ))
        fig_s.update_layout(title="Alert Status Distribution",
            template="plotly_dark",plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
            height=300,margin=dict(t=40,b=0,l=0,r=0))
        st.plotly_chart(fig_s, use_container_width=True)

    # Trend from analytics service
    st.markdown("#### Alert Trend")
    trends, t_err = api.get_fraud_trends(period=period, granularity="day")
    if trends and trends.get("points"):
        df_t = pd.DataFrame(trends["points"])
        fig_t = go.Figure()
        fig_t.add_trace(go.Scatter(
            x=df_t["date"], y=df_t["alert_count"], name="Total",
            line=dict(color="#3b82f6",width=2), fill="tozeroy",
            fillcolor="rgba(59,130,246,0.1)",
        ))
        if "fraud_count" in df_t.columns:
            fig_t.add_trace(go.Scatter(
                x=df_t["date"], y=df_t["fraud_count"], name="Fraud (HIGH+CRIT)",
                line=dict(color="#ef4444",width=2),
            ))
        fig_t.update_layout(
            template="plotly_dark",plot_bgcolor="#0f1117",paper_bgcolor="#0f1117",
            legend=dict(orientation="h",y=1.08),height=300,margin=dict(t=10,b=0,l=0,r=0))
        st.plotly_chart(fig_t, use_container_width=True)
    else:
        st.warning(f"Trend data unavailable: {t_err}")
