"""
Analytics Page — fully dynamic, no mock data.
All charts pull from the analytics-service REST API.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

from utils import api

st.set_page_config(page_title="Analytics", page_icon="📈", layout="wide")

st.markdown("# 📈 Analytics & Reporting")
st.markdown("All data sourced live from the analytics-service (PostgreSQL + MongoDB).")
st.markdown("---")

period_opts = {"Last 24 h":"24h","Last 7 days":"7d","Last 30 days":"30d"}
period_sel  = st.selectbox("Global Period", list(period_opts.keys()), index=1)
period      = period_opts[period_sel]

tab_trends, tab_geo, tab_perf, tab_customers, tab_txvol = st.tabs([
    "Alert Trends","Geographic Risk","Model Performance","Top Risky Customers","Transaction Volume",
])

# ── Tab 1: Alert Trends ────────────────────────────────────────────────────────
with tab_trends:
    st.subheader("Fraud Alert Trend")
    gran = st.selectbox("Granularity",["day","hour","week"], key="gran")
    trends, t_err = api.get_fraud_trends(period=period, granularity=gran)
    if not trends or not trends.get("points"):
        st.error(f"Analytics service unavailable: {t_err}. Start analytics-service with `make run`.")
        df = pd.DataFrame()
    else:
        df = pd.DataFrame(trends["points"])

    if df.empty:
        st.info("No trend data available — DB is empty or analytics-service is starting up.")
    else:
        fig1 = go.Figure()
        fig1.add_trace(go.Scatter(
            x=df["date"], y=df["alert_count"], name="All Alerts",
            fill="tozeroy", line=dict(color="#3b82f6", width=1.5),
            fillcolor="rgba(59,130,246,0.15)",
        ))
        if "fraud_count" in df.columns:
            fig1.add_trace(go.Scatter(
                x=df["date"], y=df["fraud_count"], name="HIGH+CRITICAL",
                fill="tozeroy", line=dict(color="#ef4444", width=1.5),
                fillcolor="rgba(239,68,68,0.2)",
            ))
        fig1.update_layout(
            title=f"Alert Volume ({period})",
            template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            legend=dict(orientation="h", y=1.08),
            height=340, margin=dict(t=40, b=0, l=0, r=0),
        )
        st.plotly_chart(fig1, use_container_width=True)

        if "fraud_rate" in df.columns:
            df["fraud_rate_pct"] = (df["fraud_rate"]*100).round(3)
            fig2 = go.Figure(go.Scatter(
                x=df["date"], y=df["fraud_rate_pct"],
                name="Fraud Rate (%)", fill="tozeroy",
                line=dict(color="#eab308", width=2),
                fillcolor="rgba(234,179,8,0.1)",
            ))
            fig2.add_hline(y=df["fraud_rate_pct"].mean(), line_dash="dash",
                           line_color="#6b7280",
                           annotation_text=f"Avg {df['fraud_rate_pct'].mean():.2f}%",
                           annotation_position="right")
            fig2.update_layout(
                title="Daily Fraud Rate (%)",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=260, margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig2, use_container_width=True)

        if "avg_fraud_prob" in df.columns:
            fig3 = go.Figure(go.Scatter(
                x=df["date"], y=(df["avg_fraud_prob"]*100).round(2),
                name="Avg Fraud Prob (%)", line=dict(color="#a855f7", width=2),
            ))
            fig3.update_layout(
                title="Average Fraud Probability Over Time",
                yaxis_title="Avg Fraud Prob (%)",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=240, margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig3, use_container_width=True)

        with st.expander("Raw Data"):
            st.dataframe(df, use_container_width=True)

# ── Tab 2: Geographic Risk ─────────────────────────────────────────────────────
with tab_geo:
    st.subheader("Geographic Fraud Distribution")
    geo_data, g_err = api.get_geo_distribution(period=period)
    if not geo_data or not geo_data.get("points"):
        st.error(f"Geographic data unavailable: {g_err}. Start analytics-service with `make run`.")
        st.info("No geographic data available yet.")
    else:
        df_geo = pd.DataFrame(geo_data["points"])
        df_geo.rename(columns={
            "CountryCode":"code","AlertCount":"alerts",
            "TxCount":"tx_count","FraudRate":"fraud_rate","TotalAmount":"total_amount",
        }, inplace=True)
        if "code" not in df_geo.columns and "country_code" in df_geo.columns:
            df_geo.rename(columns={"country_code":"code"}, inplace=True)

        fig_map = go.Figure(go.Choropleth(
            locations=df_geo["code"],
            z=df_geo["alerts"],
            text=df_geo.apply(
                lambda r: f"{r.get('code','?')}<br>Alerts: {r.get('alerts',0)}<br>"
                          f"Fraud Rate: {r.get('fraud_rate',0)*100:.1f}%", axis=1
            ),
            hovertemplate="%{text}<extra></extra>",
            colorscale=[[0,"#22c55e"],[0.5,"#eab308"],[1,"#ef4444"]],
            colorbar=dict(title="Alerts"),
        ))
        fig_map.update_layout(
            geo=dict(showframe=False, showcoastlines=True,
                     bgcolor="#0f1117", lakecolor="#0f1117",
                     landcolor="#1a1d27", coastlinecolor="#374151"),
            template="plotly_dark", paper_bgcolor="#0f1117",
            height=420, margin=dict(t=0,b=0,l=0,r=0),
            title=f"Alert Density by Country ({period})",
        )
        st.plotly_chart(fig_map, use_container_width=True)

        df_geo_sorted = df_geo.sort_values("alerts", ascending=True).tail(15)
        fig_bar = go.Figure(go.Bar(
            x=df_geo_sorted["alerts"], y=df_geo_sorted["code"],
            orientation="h", marker_color="#3b82f6",
            text=df_geo_sorted["alerts"], textposition="outside",
        ))
        fig_bar.update_layout(
            title="Top 15 Countries by Alert Count",
            template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            height=380, margin=dict(t=40,b=0,l=0,r=0), showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)
        st.dataframe(df_geo.sort_values("alerts",ascending=False), use_container_width=True, hide_index=True)

# ── Tab 3: Model Performance ───────────────────────────────────────────────────
with tab_perf:
    st.subheader("Live Model Performance (from alert feedback loop)")
    st.caption(
        "TP = alerts resolved as confirmed fraud. FP = alerts marked false positive. "
        "Derived from real alert status transitions in PostgreSQL."
    )
    perf_data, p_err = api.get_model_performance_live(period=period)
    if not perf_data:
        st.error(f"Model performance unavailable: {p_err}")
        # Still show benchmark table from ML service
    else:
        p = perf_data
        m1,m2,m3,m4,m5 = st.columns(5)
        m1.metric("Total Predictions",   f"{p.get('TotalPredictions',0):,}")
        m2.metric("True Positives",       p.get("TruePositives",0))
        m3.metric("False Positives",      p.get("FalsePositives",0))
        m4.metric("Precision",            f"{p.get('Precision',0)*100:.1f}%")
        m5.metric("Recall (approx)",      f"{p.get('Recall',0)*100:.1f}%")

        tp = p.get("TruePositives",0)
        fp = p.get("FalsePositives",0)
        if tp+fp > 0:
            fig_cm = go.Figure(go.Heatmap(
                z=[[0, fp],[0, tp]],
                x=["Pred Licit","Pred Fraud"],
                y=["Actual Licit","Actual Fraud"],
                colorscale=[[0,"#1a1d27"],[1,"#3b82f6"]],
                showscale=False,
                text=[[f"—", f"FP: {fp:,}"],[f"—", f"TP: {tp:,}"]],
                texttemplate="%{text}",
            ))
            fig_cm.update_layout(
                title="Confusion Matrix (observable cells only)",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=280, margin=dict(t=40,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_cm, use_container_width=True)

    # Benchmark from ML service
    st.markdown("---")
    st.markdown("#### Benchmark Results (ML Service — Elliptic Dataset)")
    comp, c_err = api.get_model_comparison()
    if comp and comp.get("models"):
        df_m = pd.DataFrame(comp["models"])
        mc   = {"lightgbm":"#22c55e","random_forest":"#3b82f6","xgboost":"#f97316",
                "gnn":"#a855f7","autoencoder":"#6b7280"}
        fig_b = go.Figure()
        for metric,color in [("precision","#3b82f6"),("recall","#22c55e"),("f1_score","#f97316")]:
            fig_b.add_trace(go.Bar(
                x=df_m["model_name"], y=(df_m[metric]*100).round(2),
                name=metric.replace("_"," ").title(), marker_color=color,
            ))
        fig_b.update_layout(
            barmode="group",
            template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            legend=dict(orientation="h",y=1.1),
            height=320, margin=dict(t=40,b=0,l=0,r=0),
        )
        st.plotly_chart(fig_b, use_container_width=True)
    else:
        st.warning(f"ML service benchmark unavailable: {c_err}")

# ── Tab 4: Top Risky Customers ─────────────────────────────────────────────────
with tab_customers:
    st.subheader("Top Risky Customers")
    lim = st.slider("Number of customers", 5, 50, 10)
    cust_data, cu_err = api.get_top_customers(period=period, limit=lim)
    if not cust_data or not cust_data.get("customers"):
        st.error(f"Customer data unavailable: {cu_err}. Start analytics-service with `make run`.")
        st.info("No customer data available yet.")
    else:
        customers = cust_data["customers"]
        df_c = pd.DataFrame(customers)
        df_c.rename(columns={
            "CustomerID":"customer_id","AlertCount":"alert_count",
            "FraudRate":"fraud_rate","TotalAmount":"total_amount",
            "AvgRiskScore":"avg_risk_score","LastAlertAt":"last_alert_at",
        }, inplace=True)

        df_c_sorted = df_c.sort_values("alert_count", ascending=True)
        fig_c = go.Figure(go.Bar(
            x=df_c_sorted["alert_count"],
            y=df_c_sorted["customer_id"].str[:12] + "…",
            orientation="h",
            marker_color=["#ef4444" if r > 0.5 else "#f97316" if r > 0.3 else "#3b82f6"
                          for r in df_c_sorted.get("fraud_rate", pd.Series([0]*len(df_c_sorted)))],
            text=df_c_sorted["alert_count"],
            textposition="outside",
        ))
        fig_c.update_layout(
            title=f"Alert Count — Top {lim} Risky Customers",
            template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            height=max(300, len(customers)*30), margin=dict(t=40,b=0,l=0,r=0),
            showlegend=False,
        )
        st.plotly_chart(fig_c, use_container_width=True)

        if "fraud_rate" in df_c.columns and "total_amount" in df_c.columns:
            fig_s = px.scatter(
                df_c, x="total_amount", y="fraud_rate",
                size="alert_count", color="avg_risk_score",
                hover_data=["customer_id","alert_count"],
                color_continuous_scale=["#22c55e","#eab308","#ef4444"],
                labels={"total_amount":"Total Volume (USD)","fraud_rate":"Fraud Rate","avg_risk_score":"Risk Score"},
                title="Fraud Rate vs Transaction Volume",
            )
            fig_s.update_layout(
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=340, margin=dict(t=40,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_s, use_container_width=True)

        st.dataframe(df_c, use_container_width=True, hide_index=True)

# ── Tab 5: Transaction Volume ──────────────────────────────────────────────────
with tab_txvol:
    st.subheader("Transaction Volume")
    vol_gran = st.selectbox("Granularity",["day","hour","week"], key="vol_gran")
    vol_data, v_err = api.get_transaction_volume(period=period, granularity=vol_gran)
    if not vol_data or not vol_data.get("points"):
        st.error(f"Transaction volume unavailable: {v_err}. Start analytics-service with `make run`.")
        st.info("No transaction volume data available yet.")
    else:
        df_tx = pd.DataFrame(vol_data["points"])

        col_l, col_r = st.columns(2)
        with col_l:
            fig_v = go.Figure()
            fig_v.add_trace(go.Bar(
                x=df_tx["date"], y=df_tx["total_count"],
                name="Total Transactions", marker_color="#3b82f6",
            ))
            if "flagged_count" in df_tx.columns:
                fig_v.add_trace(go.Bar(
                    x=df_tx["date"], y=df_tx["flagged_count"],
                    name="Flagged", marker_color="#ef4444",
                ))
            fig_v.update_layout(
                barmode="overlay", title="Daily Transaction Count",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                legend=dict(orientation="h",y=1.1),
                height=320, margin=dict(t=40,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_v, use_container_width=True)

        with col_r:
            fig_a = go.Figure(go.Scatter(
                x=df_tx["date"], y=df_tx["total_volume"],
                name="Volume (USD)", fill="tozeroy",
                line=dict(color="#a855f7", width=2),
                fillcolor="rgba(168,85,247,0.1)",
            ))
            fig_a.update_layout(
                title="Daily Transaction Volume (USD)",
                yaxis_title="USD",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=320, margin=dict(t=40,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_a, use_container_width=True)

        if "flagged_count" in df_tx.columns and "total_count" in df_tx.columns:
            df_tx["flag_rate"] = (df_tx["flagged_count"]/df_tx["total_count"].replace(0,1)*100).round(2)
            fig_fr = go.Figure(go.Scatter(
                x=df_tx["date"], y=df_tx["flag_rate"],
                fill="tozeroy", line=dict(color="#eab308",width=2),
                fillcolor="rgba(234,179,8,0.1)",
            ))
            fig_fr.add_hline(y=df_tx["flag_rate"].mean(), line_dash="dash",
                             line_color="#6b7280",
                             annotation_text=f"Avg {df_tx['flag_rate'].mean():.2f}%")
            fig_fr.update_layout(
                title="Daily Alert Flag Rate (%)",
                template="plotly_dark", plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=260, margin=dict(t=40,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_fr, use_container_width=True)

        st.markdown("#### Summary")
        summ = {
            "Metric":["Total Transactions","Total Volume (USD)","Avg Daily Volume","Total Flagged","Avg Flag Rate","Avg Tx Amount"],
            "Value":[
                f"{df_tx['total_count'].sum():,}",
                f"${df_tx['total_volume'].sum():,.0f}",
                f"${df_tx['total_volume'].mean():,.0f}",
                f"{df_tx['flagged_count'].sum():,}" if "flagged_count" in df_tx.columns else "0",
                f"{df_tx['flag_rate'].mean():.2f}%" if "flag_rate" in df_tx.columns else "—",
                f"${df_tx['avg_amount'].mean():,.0f}" if "avg_amount" in df_tx.columns else "—",
            ],
        }
        st.dataframe(pd.DataFrame(summ), use_container_width=True, hide_index=True)
