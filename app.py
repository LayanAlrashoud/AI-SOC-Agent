import streamlit as st
import pandas as pd
from ai_agent import analyze_alert
from wazuh_client import fetch_alerts, get_available_agents

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")
st.title("AI SOC Alert Dashboard")
st.write("Fetch all alerts, filter by time and client, then analyze selected alerts with AI.")

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None

# Filters
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

if fetch_button:
    try:
        st.session_state.alerts = fetch_alerts(
            time_from=time_filter,
            agent_name=agent_filter,
            size=500
        )
        st.success(f"Loaded {len(st.session_state.alerts)} alerts.")
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")

# Show alerts
st.subheader("Alerts")

if st.session_state.alerts:
    table_data = []
    for i, alert in enumerate(st.session_state.alerts):
        table_data.append({
            "index": i,
            "timestamp": alert["timestamp"],
            "agent_name": alert["agent_name"],
            "severity": alert["severity"],
            "rule_description": alert["rule_description"],
            "source_ip": alert["source_ip"]
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)

    selected_index = st.number_input(
        "Enter alert index to inspect",
        min_value=0,
        max_value=len(st.session_state.alerts) - 1,
        step=1
    )

    if st.button("Load Selected Alert"):
        st.session_state.selected_alert = st.session_state.alerts[selected_index]

# Selected alert
if st.session_state.selected_alert:
    st.subheader("Selected Alert")
    st.json(st.session_state.selected_alert)

    if st.button("Analyze Selected Alert with AI"):
        try:
            result = analyze_alert(st.session_state.selected_alert)

            left, right = st.columns(2)

            with left:
                st.subheader("Alert Details")
                st.json(st.session_state.selected_alert)

            with right:
                st.subheader("AI Analysis")
                st.json(result)

            st.subheader("Incident Summary")
            st.markdown(f"**Incident Type:** {result.get('incident_type', 'unknown')}")
            st.markdown(f"**Severity:** {result.get('severity', 'unknown')}")
            st.markdown(f"**Source IP:** {result.get('source_ip', 'unknown')}")
            st.markdown(f"**Target Host:** {result.get('target_host', 'unknown')}")
            st.markdown(f"**Confidence:** {result.get('confidence', 'unknown')}")

            st.subheader("Explanation")
            st.write(result.get("explanation", "No explanation returned."))

            st.subheader("Recommended Actions")
            actions = result.get("recommended_actions", [])
            if actions:
                for action in actions:
                    st.markdown(f"- {action}")
            else:
                st.write("No actions returned.")

        except Exception as e:
            st.error(f"Analysis failed: {e}")