import streamlit as st
import pandas as pd
from ai_agent import analyze_alert
from wazuh_client import fetch_alerts, get_available_agents

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")

st.title("AI SOC Alert Dashboard")
st.write("Fetch Wazuh alerts, filter by time and client, then analyze any selected alert with AI.")

# ----------------------------
# Session state
# ----------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

# ----------------------------
# Filters
# ----------------------------
st.subheader("Filters")

col1, col2, col3 = st.columns(3)

with col1:
    time_filter = st.selectbox(
        "Time Range",
        options=["now-1h", "now-6h", "now-24h", "now-7d", "now-30d"],
        index=2
    )

with col2:
    try:
        agents = get_available_agents()
    except Exception:
        agents = ["All"]
    agent_filter = st.selectbox("Client / Agent", options=agents)

with col3:
    fetch_button = st.button("Fetch Alerts")

# ----------------------------
# Fetch alerts
# ----------------------------
if fetch_button:
    try:
        alerts = fetch_alerts(
            time_from=time_filter,
            agent_name=agent_filter,
            size=500
        )
        st.session_state.alerts = alerts
        st.session_state.selected_alert = None
        st.session_state.analysis_result = None
        st.success(f"Loaded {len(alerts)} alerts.")
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")

# ----------------------------
# Show alerts table
# ----------------------------
st.subheader("Alerts")

if st.session_state.alerts:
    table_data = []
    for i, alert in enumerate(st.session_state.alerts):
        table_data.append({
            "index": i,
            "timestamp": alert.get("timestamp", "unknown"),
            "agent_name": alert.get("agent_name", "unknown"),
            "severity": alert.get("severity", 0),
            "rule_description": alert.get("rule_description", "unknown"),
            "source_ip": alert.get("source_ip", "unknown"),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)

    st.subheader("Select Alert")

    selected_index = st.number_input(
        "Enter alert index to inspect",
        min_value=0,
        max_value=len(st.session_state.alerts) - 1,
        step=1
    )

    col_a, col_b = st.columns(2)

    with col_a:
        if st.button("Load Selected Alert"):
            st.session_state.selected_alert = st.session_state.alerts[selected_index]
            st.session_state.analysis_result = None

    with col_b:
        if st.button("Clear Selected Alert"):
            st.session_state.selected_alert = None
            st.session_state.analysis_result = None

else:
    st.info("No alerts loaded yet. Choose filters, then click 'Fetch Alerts'.")

# ----------------------------
# Show selected alert
# ----------------------------
if st.session_state.selected_alert:
    st.subheader("Selected Alert")
    st.json(st.session_state.selected_alert)

    if st.button("Analyze Selected Alert with AI"):
        try:
            result = analyze_alert(st.session_state.selected_alert)
            st.session_state.analysis_result = result
            st.success("Analysis completed.")
        except Exception as e:
            st.error(f"Analysis failed: {e}")

# ----------------------------
# Show AI analysis
# ----------------------------
if st.session_state.analysis_result:
    result = st.session_state.analysis_result

    left, right = st.columns(2)

    with left:
        st.subheader("Alert Details")
        st.json(st.session_state.selected_alert)

    with right:
        st.subheader("AI Analysis (Raw JSON)")
        st.json(result)

    st.subheader("Incident Summary")
    st.markdown(f"**Incident Type:** {result.get('incident_type', 'unknown')}")
    st.markdown(f"**Wazuh Severity:** {result.get('wazuh_severity', 'unknown')}")
    st.markdown(f"**AI Severity:** {result.get('ai_severity', 'unknown')}")
    st.markdown(f"**AI Risk Score:** {result.get('ai_risk_score', 'unknown')}/100")
    st.markdown(f"**AI Priority:** {result.get('ai_priority', 'unknown')}")
    st.markdown(f"**False Positive Likelihood:** {result.get('false_positive_likelihood', 'unknown')}")
    st.markdown(f"**Needs Human Attention:** {result.get('needs_human_attention', 'unknown')}")
    st.markdown(f"**Source IP:** {result.get('source_ip', 'unknown')}")
    st.markdown(f"**Target Host:** {result.get('target_host', 'unknown')}")
    st.markdown(f"**Confidence:** {result.get('confidence', 'unknown')}")

    st.subheader("Explanation")
    st.write(result.get("explanation", "No explanation returned."))

    st.subheader("Why It Matters")
    st.write(result.get("why_it_matters", "No impact explanation returned."))

    st.subheader("Recommended Actions")
    actions = result.get("recommended_actions", [])
    if actions:
        for action in actions:
            st.markdown(f"- {action}")
    else:
        st.write("No actions returned.")