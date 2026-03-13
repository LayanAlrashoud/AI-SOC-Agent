import streamlit as st
from ai_agent import analyze_alert
from wazuh_client import fetch_alerts, get_available_agents, get_neighbor_alerts

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")

st.title("AI SOC Alert Correlation Dashboard")
st.write(
    "Fetch Wazuh alerts, filter by time and client, then analyze any selected alert "
    "with its 5-minute neighboring context."
)

# ----------------------------
# Session state
# ----------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None

if "neighbor_alerts" not in st.session_state:
    st.session_state.neighbor_alerts = []

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
    fetch_button = st.button("Fetch Alerts", use_container_width=True)

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
        st.session_state.neighbor_alerts = []
        st.session_state.analysis_result = None
        st.success(f"Loaded {len(alerts)} alerts.")
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")

# ----------------------------
# Show alerts
# ----------------------------
st.subheader("Alerts")

if st.session_state.alerts:
    h1, h2, h3, h4, h5, h6 = st.columns([2, 2, 2, 4, 1, 1])
    h1.markdown("**Timestamp**")
    h2.markdown("**Client**")
    h3.markdown("**Source IP**")
    h4.markdown("**Rule Description**")
    h5.markdown("**Severity**")
    h6.markdown("**Action**")

    st.divider()

    for i, alert in enumerate(st.session_state.alerts):
        c1, c2, c3, c4, c5, c6 = st.columns([2, 2, 2, 4, 1, 1])

        with c1:
            st.write(alert.get("timestamp", "unknown"))

        with c2:
            st.write(alert.get("agent_name", "unknown"))

        with c3:
            st.write(alert.get("source_ip", "unknown"))

        with c4:
            st.write(alert.get("rule_description", "unknown"))

        with c5:
            st.write(alert.get("severity", 0))

        with c6:
            if st.button("Analyze", key=f"analyze_{i}"):
                try:
                    st.session_state.selected_alert = alert
                    st.session_state.neighbor_alerts = get_neighbor_alerts(
                        alert,
                        minutes=5,
                        size=100
                    )
                    st.session_state.analysis_result = analyze_alert(
                        alert,
                        st.session_state.neighbor_alerts
                    )
                    st.success("Analysis completed.")
                except Exception as e:
                    st.error(f"Analysis failed: {e}")
else:
    st.info("No alerts loaded yet. Choose filters, then click 'Fetch Alerts'.")

# ----------------------------
# Show selected alert
# ----------------------------
if st.session_state.selected_alert:
    st.divider()
    st.subheader("Selected Alert")
    st.json(st.session_state.selected_alert)

    st.subheader("Neighbor Alerts (same client + same IP within 5 minutes)")
    st.write(f"Found {len(st.session_state.neighbor_alerts)} related alerts.")

    if st.session_state.neighbor_alerts:
        nh1, nh2, nh3, nh4, nh5 = st.columns([2, 2, 2, 4, 1])
        nh1.markdown("**Timestamp**")
        nh2.markdown("**Client**")
        nh3.markdown("**Source IP**")
        nh4.markdown("**Rule Description**")
        nh5.markdown("**Severity**")

        st.divider()

        for neighbor in st.session_state.neighbor_alerts:
            n1, n2, n3, n4, n5 = st.columns([2, 2, 2, 4, 1])
            n1.write(neighbor.get("timestamp", "unknown"))
            n2.write(neighbor.get("agent_name", "unknown"))
            n3.write(neighbor.get("source_ip", "unknown"))
            n4.write(neighbor.get("rule_description", "unknown"))
            n5.write(neighbor.get("severity", 0))
    else:
        st.info("No neighbor alerts found for this alert.")

# ----------------------------
# Show AI analysis
# ----------------------------
if st.session_state.analysis_result:
    result = st.session_state.analysis_result

    st.divider()
    st.subheader("AI Incident Analysis")

    sev = result.get("ai_severity", "Unknown")
    priority = result.get("ai_priority", "Unknown")

    if sev == "Critical":
        st.error(f"AI Severity: {sev}")
    elif sev == "High":
        st.warning(f"AI Severity: {sev}")
    elif sev == "Medium":
        st.info(f"AI Severity: {sev}")
    else:
        st.success(f"AI Severity: {sev}")

    if priority == "P1":
        st.error(f"AI Priority: {priority}")
    elif priority == "P2":
        st.warning(f"AI Priority: {priority}")
    elif priority == "P3":
        st.info(f"AI Priority: {priority}")
    else:
        st.success(f"AI Priority: {priority}")

    left, right = st.columns(2)

    with left:
        st.markdown(f"**Incident Type:** {result.get('incident_type', 'unknown')}")
        st.markdown(f"**Wazuh Severity:** {result.get('wazuh_severity', 'unknown')}")
        st.markdown(f"**AI Risk Score:** {result.get('ai_risk_score', 'unknown')}/100")
        st.markdown(f"**False Positive Likelihood:** {result.get('false_positive_likelihood', 'unknown')}")
        st.markdown(f"**Needs Human Attention:** {result.get('needs_human_attention', 'unknown')}")

    with right:
        st.markdown(f"**Source IP:** {result.get('source_ip', 'unknown')}")
        st.markdown(f"**Target Host:** {result.get('target_host', 'unknown')}")
        st.markdown(f"**Neighbor Alerts Count:** {result.get('neighbor_alerts_count', 'unknown')}")
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