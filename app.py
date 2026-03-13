import json
import streamlit as st
from ai_agent import analyze_alert
from wazuh_client import get_latest_100_alerts

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")
st.title("AI SOC Alert Triage Dashboard")
st.write("Fetch the latest 100 Wazuh alerts, filter risky ones, and analyze any alert with AI.")


def is_risky(alert):
    severity = alert.get("severity", 0)
    desc = str(alert.get("rule_description", "")).lower()
    groups = [g.lower() for g in alert.get("groups", [])]

    risky_keywords = [
        "authentication failed",
        "multiple authentication failures",
        "brute force",
        "sudo",
        "root",
        "privilege escalation",
        "sshd",
        "failed password",
        "integrity",
        "malware",
        "suspicious",
        "attack",
        "rootcheck"
    ]

    if severity >= 7:
        return True

    if any(keyword in desc for keyword in risky_keywords):
        return True

    if any(group in ["authentication_failed", "sudo", "sshd", "attack", "rootcheck"] for group in groups):
        return True

    return False


if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "filtered_alerts" not in st.session_state:
    st.session_state.filtered_alerts = []

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None


col1, col2 = st.columns(2)

with col1:
    if st.button("Fetch Latest 100 Alerts"):
        try:
            alerts = get_latest_100_alerts()
            st.session_state.alerts = alerts
            st.session_state.filtered_alerts = [a for a in alerts if is_risky(a)]
            st.success(f"Loaded {len(alerts)} alerts. Found {len(st.session_state.filtered_alerts)} risky alerts.")
        except Exception as e:
            st.error(f"Failed to fetch alerts: {e}")

with col2:
    if st.button("Clear"):
        st.session_state.alerts = []
        st.session_state.filtered_alerts = []
        st.session_state.selected_alert = None


st.subheader("Risky Alerts Only")

if st.session_state.filtered_alerts:
    options = [
        f"{i+1}. [{a['severity']}] {a['timestamp']} | {a['agent_name']} | {a['rule_description']}"
        for i, a in enumerate(st.session_state.filtered_alerts)
    ]

    selected_option = st.selectbox("Choose an alert to inspect", options)

    selected_index = options.index(selected_option)
    st.session_state.selected_alert = st.session_state.filtered_alerts[selected_index]

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

else:
    st.info("No risky alerts loaded yet. Click 'Fetch Latest 100 Alerts'.")