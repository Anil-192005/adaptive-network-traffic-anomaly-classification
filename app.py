"""
app.py - Streamlit Frontend for Adaptive Network Traffic Anomaly Classification
Capstone Project: Adaptive Network Traffic Anomaly Classification

Provides an interactive user interface for network analysts and system administrators
to input network flow metrics, validate parameters, and query the FastAPI backend
for real-time anomaly classification and risk scoring.
"""

import os
import json
import requests
import streamlit as st
import pandas as pd

# ---------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Network Traffic Anomaly Classifier",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for crisp, modern cyber-telemetry aesthetics
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .status-card {
        padding: 1.2rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border: 1px solid #E2E8F0;
    }
    .anomaly-badge {
        padding: 0.4rem 0.8rem;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
        font-size: 0.95rem;
    }
    .risk-critical { background-color: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
    .risk-high { background-color: #FFEDD5; color: #9A3412; border: 1px solid #FB923C; }
    .risk-medium { background-color: #FEF3C7; color: #92400E; border: 1px solid #FCD34D; }
    .risk-low { background-color: #DCFCE7; color: #166534; border: 1px solid #86EFAC; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Sidebar Configuration & Backend Connectivity Check
# ---------------------------------------------------------
st.sidebar.title("⚙️ System Control")

# Resolve default backend API URL:
# 1. Streamlit Secrets (st.secrets["BACKEND_API_URL"])
# 2. Environment Variable (BACKEND_API_URL)
# 3. Localhost Fallback ("http://127.0.0.1:8000")
default_api_url = "http://127.0.0.1:8000"
try:
    if "BACKEND_API_URL" in st.secrets:
        default_api_url = st.secrets["BACKEND_API_URL"]
except Exception:
    pass

default_api_url = os.getenv("BACKEND_API_URL", default_api_url).rstrip("/")

api_base_url = st.sidebar.text_input("FastAPI Backend URL", value=default_api_url).rstrip("/")

# Check Backend Health (allowing sufficient timeout for Render free-tier cold-starts)
backend_online = False
active_model_name = "N/A"
try:
    health_resp = requests.get(f"{api_base_url}/health", timeout=6.0)
    if health_resp.status_code == 200:
        backend_info = health_resp.json()
        if backend_info.get("model_loaded"):
            backend_online = True
            active_model_name = backend_info.get("active_model", "Loaded")
            st.sidebar.success(f"● Backend Connected\nActive Model: {active_model_name}")
        else:
            st.sidebar.warning("● Backend Online, but Model not loaded!")
    else:
        st.sidebar.error("● Backend Returned Non-200 Status")
except Exception:
    st.sidebar.error("● Backend Offline / Sleeping")
    if "onrender.com" in api_base_url:
        st.sidebar.info("⏳ Render free-tier services spin down after 15 min of inactivity. Please allow ~30-45 seconds for initial wake-up.")

st.sidebar.markdown("---")
st.sidebar.subheader("📋 Preset Traffic Scenarios")
st.sidebar.caption("Select a preset scenario to auto-populate flow features:")

preset_scenario = st.sidebar.selectbox(
    "Choose Preset Scenario",
    [
        "Custom Input",
        "Normal: Web Browsing (HTTPS)",
        "Normal: DNS Resolution",
        "Anomaly: TCP SYN Flood Attack",
        "Anomaly: Aggressive Port Scan",
        "Anomaly: Heavy Data Exfiltration"
    ]
)

# Preset feature profiles
PRESETS = {
    "Normal: Web Browsing (HTTPS)": {
        "flow_duration": 14.50,
        "packet_count": 68,
        "byte_count": 62400,
        "protocol_type": "TCP",
        "service": "HTTPS",
        "flag": "SF"
    },
    "Normal: DNS Resolution": {
        "flow_duration": 0.08,
        "packet_count": 2,
        "byte_count": 148,
        "protocol_type": "UDP",
        "service": "DNS",
        "flag": "SF"
    },
    "Anomaly: TCP SYN Flood Attack": {
        "flow_duration": 2.10,
        "packet_count": 1450,
        "byte_count": 87000,
        "protocol_type": "TCP",
        "service": "HTTP",
        "flag": "S0"
    },
    "Anomaly: Aggressive Port Scan": {
        "flow_duration": 0.015,
        "packet_count": 2,
        "byte_count": 96,
        "protocol_type": "TCP",
        "service": "SSH",
        "flag": "REJ"
    },
    "Anomaly: Heavy Data Exfiltration": {
        "flow_duration": 95.0,
        "packet_count": 4500,
        "byte_count": 6450000,
        "protocol_type": "TCP",
        "service": "FTP",
        "flag": "SF"
    }
}

current_defaults = PRESETS.get(preset_scenario, {
    "flow_duration": 5.20,
    "packet_count": 25,
    "byte_count": 18500,
    "protocol_type": "TCP",
    "service": "HTTP",
    "flag": "SF"
})

# ---------------------------------------------------------
# Main Application Header
# ---------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Adaptive Network Traffic Anomaly Classifier</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Zero-cost, foundational machine learning service for real-time network flow telemetry inspection and cyber threat detection.</div>',
    unsafe_allow_html=True
)

# ---------------------------------------------------------
# Input Form
# ---------------------------------------------------------
st.subheader("1. Network Flow Telemetry Inputs")

with st.form("network_flow_form"):
    col1, col2, col3 = st.columns(3)
    
    with col1:
        flow_duration = st.number_input(
            "Flow Duration (seconds)",
            min_value=0.0001,
            max_value=3600.0,
            value=float(current_defaults["flow_duration"]),
            step=0.1,
            format="%.4f",
            help="Total elapsed time of the network connection or conversation."
        )
        packet_count = st.number_input(
            "Packet Count",
            min_value=1,
            max_value=1000000,
            value=int(current_defaults["packet_count"]),
            step=1,
            help="Total count of packets exchanged during this flow."
        )

    with col2:
        byte_count = st.number_input(
            "Byte Count (Bytes)",
            min_value=20,
            max_value=100000000,
            value=int(current_defaults["byte_count"]),
            step=100,
            help="Total volume of bytes transferred (payload + headers)."
        )
        
        protocols = ["TCP", "UDP", "ICMP"]
        proto_idx = protocols.index(current_defaults["protocol_type"]) if current_defaults["protocol_type"] in protocols else 0
        protocol_type = st.selectbox(
            "Protocol Type",
            protocols,
            index=proto_idx,
            help="Transport protocol encapsulated."
        )

    with col3:
        services = ["HTTPS", "HTTP", "DNS", "SSH", "FTP", "OTHER"]
        serv_idx = services.index(current_defaults["service"]) if current_defaults["service"] in services else 0
        service = st.selectbox(
            "Application Service",
            services,
            index=serv_idx,
            help="Destination network application or protocol service."
        )
        
        flags = ["SF", "S0", "REJ", "RSTO", "OTH"]
        flag_idx = flags.index(current_defaults["flag"]) if current_defaults["flag"] in flags else 0
        flag = st.selectbox(
            "Connection Flag / Status",
            flags,
            index=flag_idx,
            help="SF: Normal establishment/teardown; S0: SYN with no ACK; REJ: Rejected; RSTO: Reset."
        )

    # Automatically compute derived rate features for inspection
    calc_pkt_rate = round(packet_count / max(flow_duration, 0.0001), 4)
    calc_byte_rate = round(byte_count / max(flow_duration, 0.0001), 4)

    st.markdown("#### Computed Flow Rates")
    rate_col1, rate_col2, rate_col3 = st.columns(3)
    rate_col1.metric("Packet Rate", f"{calc_pkt_rate:,.2f} pkts/sec")
    rate_col2.metric("Byte Rate", f"{calc_byte_rate:,.2f} B/sec")
    rate_col3.metric("Avg Packet Size", f"{round(byte_count / packet_count, 1)} bytes")

    submit_button = st.form_submit_button("🔍 Classify Network Flow", use_container_width=True)

# ---------------------------------------------------------
# Classification & Results Rendering
# ---------------------------------------------------------
if submit_button:
    payload = {
        "flow_duration": flow_duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packet_rate": calc_pkt_rate,
        "byte_rate": calc_byte_rate,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag
    }
    
    st.subheader("2. Classification Results & Threat Assessment")
    
    if backend_online:
        with st.spinner("Transmitting flow metrics to FastAPI backend for inference..."):
            try:
                response = requests.post(f"{api_base_url}/predict", json=payload, timeout=5.0)
                if response.status_code == 200:
                    result = response.json()
                    is_anomaly = result["is_anomaly"]
                    prob = result["anomaly_probability"]
                    risk = result["risk_level"]
                    conf = result["confidence_score"]
                    model_serving = result["model_name"]
                    
                    # Display Results
                    res_col1, res_col2 = st.columns([1.2, 1.8])
                    
                    with res_col1:
                        if is_anomaly:
                            st.error("### 🚨 ANOMALY DETECTED")
                            st.markdown(f"""
                            **Classification:** `<span class="anomaly-badge risk-critical">MALICIOUS / ANOMALOUS FLOW</span>`
                            """, unsafe_allow_html=True)
                        else:
                            st.success("### ✅ NORMAL TRAFFIC")
                            st.markdown(f"""
                            **Classification:** `<span class="anomaly-badge risk-low">BENIGN / NORMAL FLOW</span>`
                            """, unsafe_allow_html=True)

                        st.write(f"**Serving Model:** {model_serving}")
                        st.write(f"**Model Confidence:** {conf * 100:.1f}%")
                        st.write(f"**Inference Timestamp:** {result['processed_at']}")

                    with res_col2:
                        st.markdown(f"#### Anomaly Probability Score: **{prob * 100:.2f}%**")
                        st.progress(prob)
                        
                        risk_class_map = {
                            "CRITICAL": "risk-critical",
                            "HIGH": "risk-high",
                            "MEDIUM": "risk-medium",
                            "LOW": "risk-low"
                        }
                        badge_class = risk_class_map.get(risk, "risk-low")
                        st.markdown(f"**Risk Severity Tier:** <span class='anomaly-badge {badge_class}'>{risk}</span>", unsafe_allow_html=True)
                        
                        if is_anomaly:
                            st.warning(
                                "⚠️ **Recommended Action:** Isolate host IP, inspect firewall rules, "
                                "and correlate with SIEM alert logs."
                            )
                        else:
                            st.info(
                                "ℹ️ **Analysis:** Flow behavior aligns with standard protocol and telemetry specifications."
                            )

                    with st.expander("📄 View Raw API JSON Response"):
                        st.json(result)

                else:
                    st.error(f"Backend API Error ({response.status_code}): {response.text}")
            except Exception as e:
                st.error(f"Failed to communicate with FastAPI backend: {e}")
    else:
        st.warning("⚠️ FastAPI Backend is currently unreachable. You can launch the backend using:")
        st.code("uvicorn api:app --host 127.0.0.1 --port 8000 --reload")
        
        # Local Fallback Execution if model_pipeline.pkl exists
        if os.path.exists("model_pipeline.pkl"):
            st.info("💡 Local model artifact `model_pipeline.pkl` detected. Running local fallback prediction...")
            try:
                import joblib
                local_pipeline = joblib.load("model_pipeline.pkl")
                df_sample = pd.DataFrame([payload])
                pred_val = int(local_pipeline.predict(df_sample)[0])
                prob_val = float(local_pipeline.predict_proba(df_sample)[0][1]) if hasattr(local_pipeline, "predict_proba") else (1.0 if pred_val == 1 else 0.0)
                
                if pred_val == 1:
                    st.error(f"🚨 Local Model Prediction: **ANOMALY DETECTED** (Probability: {prob_val*100:.1f}%)")
                else:
                    st.success(f"✅ Local Model Prediction: **NORMAL FLOW** (Probability: {prob_val*100:.1f}%)")
            except Exception as ex:
                st.error(f"Local inference fallback failed: {ex}")

# ---------------------------------------------------------
# Model Performance & Metrics Dashboard Section
# ---------------------------------------------------------
st.markdown("---")
with st.expander("📊 View Model Benchmark & Evaluation Metrics"):
    metadata_file = "model_metadata.json"
    if os.path.exists(metadata_file):
        try:
            with open(metadata_file, "r") as f:
                meta = json.load(f)
            
            st.write(f"### Champion Model: **{meta.get('best_model')}**")
            best_metrics = meta.get("evaluation_metrics", {})
            
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Accuracy", f"{best_metrics.get('accuracy', 0)*100:.2f}%")
            m2.metric("Precision", f"{best_metrics.get('precision', 0)*100:.2f}%")
            m3.metric("Recall", f"{best_metrics.get('recall', 0)*100:.2f}%")
            m4.metric("F1-Score", f"{best_metrics.get('f1_score', 0):.4f}")
            m5.metric("ROC-AUC", f"{best_metrics.get('roc_auc', 0):.4f}")
            
            st.write("#### Baseline Model Comparison Table")
            if "all_candidate_metrics" in meta:
                df_compare = pd.DataFrame(meta["all_candidate_metrics"])
                st.dataframe(df_compare.drop(columns=["confusion_matrix"], errors="ignore"), use_container_width=True)
                
            if "confusion_matrix" in best_metrics:
                cm = best_metrics["confusion_matrix"]
                st.write("#### Confusion Matrix (Champion Model)")
                cm_df = pd.DataFrame(
                    cm,
                    index=["Actual Normal (0)", "Actual Anomaly (1)"],
                    columns=["Predicted Normal (0)", "Predicted Anomaly (1)"]
                )
                st.table(cm_df)
        except Exception as e:
            st.error(f"Could not load metadata file: {e}")
    else:
        st.info("Train the model using `python train.py` to generate the benchmark metrics report.")
