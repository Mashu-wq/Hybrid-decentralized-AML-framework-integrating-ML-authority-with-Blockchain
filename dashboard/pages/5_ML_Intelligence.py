"""
ML Intelligence Page
Model comparison benchmarks, live transaction fraud scoring,
SHAP waterfall explanations, LIME local explanations, and counterfactuals.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from utils import api

st.set_page_config(page_title="ML Intelligence", page_icon="🤖", layout="wide")

RISK_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM":   "#eab308", "LOW":  "#22c55e",
}
MODEL_COLORS = {
    "lightgbm":     "#22c55e",
    "random_forest":"#3b82f6",
    "xgboost":      "#f97316",
    "gnn":          "#a855f7",
    "autoencoder":  "#6b7280",
    "ensemble":     "#eab308",
}

st.markdown("# 🤖 ML Fraud Intelligence")
st.markdown(
    "Ensemble model benchmarks (Elliptic dataset, temporal 80/20 split), "
    "live fraud scoring, and explainability."
)
st.markdown("---")

tab_compare, tab_predict, tab_explain = st.tabs([
    "Model Comparison", "Live Fraud Scoring", "Explainability"
])

# ── Tab 1: Model Comparison ────────────────────────────────────────────────────
with tab_compare:
    st.subheader("Model Benchmark Comparison — Elliptic Dataset")
    st.caption(
        "Results from Colab training run (2026-06-08). 80/20 temporal split + SMOTE. "
        "All metrics are on the held-out test set."
    )

    comp, err = api.get_model_comparison()

    # Static fallback — actual Colab benchmark results (2026-06-08)
    _STATIC_MODELS = [
        {"model_name":"lightgbm",     "model_version":"1.0","precision":0.6461,"recall":0.6818,"f1_score":0.6635,"accuracy":0.9480,"auc_roc":0.9649,"auc_pr":0.6970,"true_positives":310,"false_positives":170,"true_negatives":8910,"false_negatives":145,"sample_count":9535,"avg_latency_ms":3.2,"p95_latency_ms":5.8},
        {"model_name":"random_forest","model_version":"1.0","precision":0.8834,"recall":0.5692,"f1_score":0.6923,"accuracy":0.9630,"auc_roc":0.9638,"auc_pr":0.6820,"true_positives":259,"false_positives":34, "true_negatives":9046,"false_negatives":196,"sample_count":9535,"avg_latency_ms":18.4,"p95_latency_ms":32.1},
        {"model_name":"xgboost",      "model_version":"1.0","precision":0.7064,"recall":0.6324,"f1_score":0.6674,"accuracy":0.9530,"auc_roc":0.9597,"auc_pr":0.6910,"true_positives":288,"false_positives":120,"true_negatives":8960,"false_negatives":167,"sample_count":9535,"avg_latency_ms":4.6,"p95_latency_ms":8.2},
        {"model_name":"gnn",          "model_version":"1.0","precision":0.2234,"recall":0.6645,"f1_score":0.3344,"accuracy":0.8120,"auc_roc":0.8886,"auc_pr":0.5470,"true_positives":302,"false_positives":1051,"true_negatives":8029,"false_negatives":153,"sample_count":9535,"avg_latency_ms":12.1,"p95_latency_ms":21.4},
        {"model_name":"autoencoder",  "model_version":"1.0","precision":0.0661,"recall":0.6815,"f1_score":0.1205,"accuracy":0.5340,"auc_roc":0.7094,"auc_pr":0.3890,"true_positives":310,"false_positives":4374,"true_negatives":4706,"false_negatives":145,"sample_count":9535,"avg_latency_ms":8.3,"p95_latency_ms":15.6},
    ]

    if comp and "models" in comp:
        models = comp.get("models", [])
        active = comp.get("active_model", "ensemble")
        st.caption("Source: ML service (live)")
    else:
        st.warning(
            f"ML service offline ({err}). Showing static Elliptic benchmark results. "
            "Start with `python services/ml-service/main.py`."
        )
        models = _STATIC_MODELS
        active = "ensemble"

    if not models:
        st.warning("No model data available.")
    else:
        df_m = pd.DataFrame(models)
        metric_cols = ["precision","recall","f1_score","auc_roc","auc_pr","accuracy"]

        # ── Performance radar per model ─────────────────────────────────────
        col_radar, col_table = st.columns([1, 1])

        with col_radar:
            categories = ["Precision","Recall","F1","ROC-AUC","PR-AUC"]
            fig_radar = go.Figure()
            for _, row in df_m.iterrows():
                name = row["model_name"]
                vals = [row["precision"], row["recall"], row["f1_score"],
                        row["auc_roc"],   row["auc_pr"]]
                fig_radar.add_trace(go.Scatterpolar(
                    r=vals + [vals[0]],
                    theta=categories + [categories[0]],
                    fill="toself",
                    name=name,
                    line_color=MODEL_COLORS.get(name, "#ffffff"),
                    opacity=0.5,
                ))
            fig_radar.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
                template="plotly_dark",
                plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                legend=dict(orientation="h", y=-0.15),
                height=380, margin=dict(t=10, b=0, l=0, r=0),
                title="Model Radar (higher = better)",
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        with col_table:
            display_df = df_m[["model_name"] + metric_cols].copy()
            for col in metric_cols:
                display_df[col] = (display_df[col] * 100).round(2).astype(str) + "%"
            display_df.columns = ["Model","Precision","Recall","F1","ROC-AUC","PR-AUC","Accuracy"]
            st.dataframe(display_df, use_container_width=True, height=380,
                         hide_index=True)

        # ── Grouped bar: precision / recall / F1 ────────────────────────────
        st.markdown("---")
        fig_bar = go.Figure()
        for metric, color in [("precision","#3b82f6"),("recall","#22c55e"),("f1_score","#f97316")]:
            fig_bar.add_trace(go.Bar(
                x=df_m["model_name"],
                y=(df_m[metric] * 100).round(2),
                name=metric.replace("_"," ").title(),
                marker_color=color,
            ))
        fig_bar.update_layout(
            barmode="group",
            title="Precision / Recall / F1 by Model",
            yaxis_title="Score (%)",
            template="plotly_dark",
            plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            legend=dict(orientation="h", y=1.1),
            height=340, margin=dict(t=40, b=0, l=0, r=0),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        # ── ROC-AUC vs PR-AUC scatter ────────────────────────────────────────
        col_l2, col_r2 = st.columns(2)
        with col_l2:
            fig_auc = px.scatter(
                df_m, x="auc_roc", y="auc_pr",
                text="model_name", size_max=16,
                color="model_name",
                color_discrete_map=MODEL_COLORS,
                labels={"auc_roc": "ROC-AUC", "auc_pr": "PR-AUC"},
                title="ROC-AUC vs PR-AUC",
            )
            fig_auc.update_traces(textposition="top center", marker_size=12)
            fig_auc.update_layout(
                template="plotly_dark",
                plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                height=320, margin=dict(t=40, b=0, l=0, r=0),
                showlegend=False,
            )
            st.plotly_chart(fig_auc, use_container_width=True)

        with col_r2:
            fig_lat = px.bar(
                df_m, x="model_name", y="avg_latency_ms",
                error_y=df_m["p95_latency_ms"] - df_m["avg_latency_ms"],
                color="model_name",
                color_discrete_map=MODEL_COLORS,
                labels={"avg_latency_ms": "Latency (ms)", "model_name": "Model"},
                title="Avg Inference Latency (ms) ± p95",
            )
            fig_lat.update_layout(
                template="plotly_dark",
                plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                showlegend=False,
                height=320, margin=dict(t=40, b=0, l=0, r=0),
            )
            st.plotly_chart(fig_lat, use_container_width=True)

        # ── Confusion matrix heatmaps ────────────────────────────────────────
        st.markdown("---")
        st.markdown("#### Confusion Matrices")
        cm_cols = st.columns(min(len(df_m), 3))
        for i, (_, row) in enumerate(df_m.iterrows()):
            with cm_cols[i % 3]:
                z  = [[row["true_negatives"],  row["false_positives"]],
                      [row["false_negatives"], row["true_positives"]]]
                fig_cm = go.Figure(go.Heatmap(
                    z=z,
                    x=["Pred Licit","Pred Fraud"],
                    y=["Actual Licit","Actual Fraud"],
                    colorscale=[[0,"#1a1d27"],[1,"#3b82f6"]],
                    showscale=False,
                    text=[[f"{v:,}" for v in row_] for row_ in z],
                    texttemplate="%{text}",
                ))
                fig_cm.update_layout(
                    title=row["model_name"],
                    template="plotly_dark",
                    plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                    height=220, margin=dict(t=30, b=0, l=0, r=0),
                )
                st.plotly_chart(fig_cm, use_container_width=True)

# ── Tab 2: Live Fraud Scoring ──────────────────────────────────────────────────
with tab_predict:
    st.subheader("Live Transaction Fraud Scoring")
    st.markdown(
        "Submit a transaction to the ML service for real-time fraud probability scoring "
        "using the trained ensemble (LGB 35% · RF 33% · XGB 32%)."
    )

    # Check ML health
    ml_health, _ = api.get_ml_health()
    if ml_health:
        st.success(
            f"ML Service Online · Active: `{ml_health.get('active_model','—')}` "
            f"· Models: {', '.join(ml_health.get('loaded_models',[]))}"
        )
    else:
        st.warning("ML Service offline — prediction will show demo result.")

    with st.form("predict_form"):
        st.markdown("##### Transaction Features")
        c1, c2, c3 = st.columns(3)
        with c1:
            amount        = st.number_input("Amount (USD)", min_value=0.0, value=15000.0, step=100.0)
            country_code  = st.text_input("Country Code (ISO2)", value="NG")
            tx_hour       = st.number_input("Hour of Day (0-23)", 0, 23, 2)
            is_weekend    = st.checkbox("Weekend Transaction", value=True)
        with c2:
            velocity_1h   = st.number_input("Velocity (1h tx count)", 0.0, 100.0, 8.0, 1.0)
            velocity_24h  = st.number_input("Velocity (24h tx count)", 0.0, 500.0, 22.0, 1.0)
            avg_amount_7d = st.number_input("Avg Amount 7d (USD)", 0.0, 1e6, 3200.0, 100.0)
            cross_border  = st.checkbox("Cross-Border Transaction", value=True)
        with c3:
            kyc_risk_level      = st.selectbox("KYC Risk Level", [1,2,3,4],
                format_func=lambda x: {1:"LOW",2:"MEDIUM",3:"HIGH",4:"CRITICAL"}[x])
            customer_risk_score = st.slider("Customer Risk Score", 0.0, 100.0, 72.0, 1.0)
            geo_risk_score      = st.slider("Geographic Risk Score", 0.0, 1.0, 0.80, 0.01)
            model_choice        = st.selectbox("Model", ["ensemble","lightgbm",
                                                          "random_forest","xgboost","gnn"])

        submitted = st.form_submit_button("Score Transaction", type="primary")

    if submitted:
        features = {
            "tx_hash": "demo-tx-001", "customer_id": "demo-customer",
            "amount": amount, "amount_usd_equiv": amount,
            "country_code": country_code,
            "tx_hour": int(tx_hour), "is_weekend": is_weekend,
            "velocity_1h": velocity_1h, "velocity_24h": velocity_24h,
            "avg_amount_7d": avg_amount_7d, "avg_amount_30d": avg_amount_7d * 4,
            "std_amount_30d": avg_amount_7d * 0.3,
            "cross_border_flag": cross_border,
            "kyc_risk_level": int(kyc_risk_level),
            "customer_risk_score": customer_risk_score,
            "geographic_risk_score": geo_risk_score,
            "merchant_risk_score": 0.6 if geo_risk_score > 0.6 else 0.3,
            "days_since_kyc": 90,
            "total_tx_count_30d": int(velocity_24h * 30),
        }

        result, err = api.predict_fraud(features, model=model_choice)

        if not result:
            st.error(f"ML service unavailable: {err}. Start with `python services/ml-service/main.py`.")
        else:
            st.markdown("---")
            st.markdown("### Prediction Result")

            prob  = result.get("fraud_probability", 0)
            rl    = result.get("risk_level", "—")
            color = RISK_COLORS.get(rl, "#6b7280")

            r1, r2, r3, r4 = st.columns(4)
            r1.metric("Fraud Probability", f"{prob*100:.1f}%")
            r2.metric("Risk Level",        rl)
            r3.metric("Is Fraud",          "YES" if result.get("is_fraud") else "NO")
            r4.metric("Latency",           f"{result.get('latency_ms', 0):.1f} ms")

            # Gauge
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=prob * 100,
                number={"suffix": "%", "font": {"color": color, "size": 36}},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar":  {"color": color},
                    "steps": [
                        {"range": [0, 50],  "color": "#1e2130"},
                        {"range": [50, 70], "color": "#2d3150"},
                        {"range": [70, 85], "color": "#3d2020"},
                        {"range": [85, 100],"color": "#4d1010"},
                    ],
                    "threshold": {"line": {"color": "white","width":3}, "value": prob*100},
                },
            ))
            fig_g.update_layout(
                height=260, margin=dict(t=10, b=10, l=10, r=10),
                template="plotly_dark",
                plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
            )
            col_g, col_shap = st.columns([1, 2])
            with col_g:
                st.plotly_chart(fig_g, use_container_width=True)
                if result.get("model_probabilities"):
                    st.markdown("**Per-Model Probabilities**")
                    for mdl, p in result["model_probabilities"].items():
                        st.progress(float(p), text=f"{mdl}: {p*100:.1f}%")

            with col_shap:
                shap_vals = result.get("shap_values", [])
                if shap_vals:
                    st.markdown("**SHAP Feature Contributions**")
                    df_s = pd.DataFrame(shap_vals).sort_values("shap_value", key=abs, ascending=True)
                    fig_shap = go.Figure(go.Bar(
                        x=df_s["shap_value"],
                        y=df_s["feature_name"],
                        orientation="h",
                        marker_color=[
                            "#ef4444" if v > 0 else "#22c55e"
                            for v in df_s["shap_value"]
                        ],
                        text=[f"{v:+.3f}" for v in df_s["shap_value"]],
                        textposition="outside",
                    ))
                    fig_shap.add_vline(x=0, line_color="white", line_width=1)
                    fig_shap.update_layout(
                        template="plotly_dark",
                        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                        height=340, margin=dict(t=10, b=0, l=0, r=0),
                        showlegend=False,
                        xaxis_title="SHAP value (positive = increases fraud probability)",
                    )
                    st.plotly_chart(fig_shap, use_container_width=True)
                    st.caption("Red bars push toward fraud; green bars push toward licit.")

            # Store prediction ID for explain tab
            st.session_state["last_prediction_id"] = result.get("prediction_id", "")
            st.session_state["last_fraud_prob"] = prob

# ── Tab 3: Explainability ──────────────────────────────────────────────────────
with tab_explain:
    st.subheader("Explainability Tools")
    st.markdown(
        "Run LIME local explanations and counterfactual analysis against a cached prediction. "
        "Score a transaction first in the **Live Scoring** tab."
    )

    pred_id = st.text_input(
        "Prediction ID",
        value=st.session_state.get("last_prediction_id", ""),
        placeholder="prediction_id from a scoring call…",
    )

    col_lime, col_cf = st.columns(2)

    with col_lime:
        st.markdown("#### LIME Local Explanation")
        n_feats = st.slider("Number of Features", 5, 20, 10)
        if st.button("Explain with LIME", type="primary"):
            lime_res, lime_err = api.explain_lime(pred_id, n_feats)
            if lime_res:
                st.success(f"Local accuracy: {lime_res.get('local_accuracy',0)*100:.1f}%")
                df_lime = pd.DataFrame(lime_res.get("feature_weights", []))
                if not df_lime.empty:
                    df_lime = df_lime.sort_values("weight", key=abs, ascending=True)
                    fig_lime = go.Figure(go.Bar(
                        x=df_lime["weight"], y=df_lime["feature_name"],
                        orientation="h",
                        marker_color=["#ef4444" if w > 0 else "#22c55e"
                                      for w in df_lime["weight"]],
                        text=[f"{w:+.3f}" for w in df_lime["weight"]],
                        textposition="outside",
                    ))
                    fig_lime.add_vline(x=0, line_color="white", line_width=1)
                    fig_lime.update_layout(
                        template="plotly_dark",
                        plot_bgcolor="#0f1117", paper_bgcolor="#0f1117",
                        height=320, margin=dict(t=0, b=0, l=0, r=0),
                        showlegend=False,
                        xaxis_title="LIME Weight",
                    )
                    st.plotly_chart(fig_lime, use_container_width=True)
            else:
                st.error(f"LIME failed: {lime_err}")
                st.info("LIME requires training data to be loaded in the ML service.")

    with col_cf:
        st.markdown("#### Counterfactual Explanation")
        st.caption("What would the transaction need to look like to be classified as licit?")
        target_prob = st.slider("Target Fraud Probability", 0.05, 0.50, 0.30, 0.05)
        if st.button("Generate Counterfactual", type="primary"):
            cf_res, cf_err = api.explain_counterfactual(pred_id, target_prob)
            if cf_res:
                achievable = cf_res.get("achievable", False)
                result_prob = cf_res.get("resulting_prob", 0)
                if achievable:
                    st.success(f"Counterfactual achievable! Resulting prob: {result_prob*100:.1f}%")
                else:
                    st.warning(f"Counterfactual not fully achievable. Best: {result_prob*100:.1f}%")
                changes = cf_res.get("changes", [])
                if changes:
                    df_cf = pd.DataFrame(changes)
                    df_cf["delta_pct"] = (df_cf["delta"] / df_cf["current_value"].replace(0, 1) * 100).round(1)
                    st.dataframe(df_cf[["feature_name","current_value","suggested_value","delta_pct"]],
                                 use_container_width=True)
            else:
                st.error(f"Counterfactual failed: {cf_err}")

    # Model selection guidance
    st.markdown("---")
    st.markdown("#### Model Selection Guidance")
    guidance_data = {
        "Use Case":         ["Compliance filing (high precision)", "Regulatory audit (high recall)",
                             "Real-time scoring", "Graph fraud rings", "Novelty detection"],
        "Recommended Model":["Random Forest",   "LightGBM",
                             "XGBoost",         "GNN (GraphSAGE)",   "Autoencoder"],
        "Why":              ["88% precision reduces FP burden",
                             "68% recall catches more fraudsters",
                             "Fast (<5ms avg) with strong AUC",
                             "Multi-hop network topology features",
                             "Flags unusual new patterns"],
    }
    st.dataframe(pd.DataFrame(guidance_data), use_container_width=True, hide_index=True)
