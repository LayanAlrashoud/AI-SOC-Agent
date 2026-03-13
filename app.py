import streamlit as st
from ai_agent import analyze_alert
from wazuh_client import fetch_alerts, get_available_agents, get_neighbor_alerts

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")

st.markdown(
    """
    <style>
    .metric-card {
        border: 1px solid rgba(250,250,250,0.12);
        border-radius: 14px;
        padding: 14px 16px;
        background-color: rgba(255,255,255,0.02);
        margin-bottom: 10px;
    }

    .tool-card {
        border: 1px solid rgba(250,250,250,0.12);
        border-radius: 14px;
        padding: 16px 18px;
        background-color: rgba(255,255,255,0.02);
        margin-bottom: 12px;
    }

    .tool-title {
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 8px;
    }

    .tool-label {
        font-weight: 600;
    }

    .mini-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 13px;
        font-weight: 600;
        border: 1px solid rgba(255,255,255,0.12);
        margin-right: 8px;
        margin-bottom: 6px;
    }

    .section-box {
        border: 1px solid rgba(250,250,250,0.10);
        border-radius: 14px;
        padding: 14px 16px;
        background-color: rgba(255,255,255,0.015);
        margin-bottom: 14px;
    }

    .alerts-note {
        opacity: 0.75;
        margin-bottom: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("AI SOC Alert Correlation Dashboard")
st.write(
    "Fetch Wazuh alerts, filter by time and client, then analyze any selected alert "
    "with its 5-minute neighboring context."
)

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None

if "neighbor_alerts" not in st.session_state:
    st.session_state.neighbor_alerts = []

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None


def severity_label(level: int) -> str:
    try:
        level = int(level)
    except Exception:
        return "Unknown"

    if level >= 13:
        return "Critical"
    if level >= 10:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"


def render_severity_box(ai_severity: str):
    sev = (ai_severity or "").strip()

    if sev == "Critical":
        st.error(f"AI Severity: {sev}")
    elif sev == "High":
        st.warning(f"AI Severity: {sev}")
    elif sev == "Medium":
        st.info(f"AI Severity: {sev}")
    else:
        st.success(f"AI Severity: {sev or 'Unknown'}")


def render_priority_box(priority: str):
    p = (priority or "").strip()

    if p == "P1":
        st.error(f"AI Priority: {p}")
    elif p == "P2":
        st.warning(f"AI Priority: {p}")
    elif p == "P3":
        st.info(f"AI Priority: {p}")
    else:
        st.success(f"AI Priority: {p or 'Unknown'}")


def render_kv_box(title: str, value: str):
    st.markdown(
        f"""
        <div class="metric-card">
            <div style="font-size:13px; opacity:0.75;">{title}</div>
            <div style="font-size:18px; font-weight:700; margin-top:4px;">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_tool_findings(findings: list):
    if not findings:
        st.write("No tool findings returned.")
        return

    for finding in findings:
        tool = finding.get("tool", "Unknown Tool")
        observable = finding.get("observable", "unknown")
        summary = finding.get("summary", "No summary provided.")

        st.markdown(
            f"""
            <div class="tool-card">
                <div class="tool-title">{tool}</div>
                <div style="margin-bottom:8px;">
                    <span class="tool-label">Observable:</span> {observable}
                </div>
                <div>
                    <span class="tool-label">Finding:</span> {summary}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_selected_alert(alert: dict):
    st.subheader("Selected Alert")

    left, right = st.columns(2)

    with left:
        render_kv_box("Timestamp", str(alert.get("timestamp", "unknown")))
        render_kv_box("Client / Agent", str(alert.get("agent_name", "unknown")))
        render_kv_box("Source IP", str(alert.get("source_ip", "unknown")))

    with right:
        render_kv_box("Rule Description", str(alert.get("rule_description", "unknown")))
        render_kv_box("Wazuh Severity", str(alert.get("severity", "unknown")))
        render_kv_box("Severity Label", severity_label(alert.get("severity", 0)))

    with st.expander("View full alert JSON"):
        st.json(alert)


def render_neighbor_alerts_table(neighbor_alerts: list):
    st.subheader("Neighbor Alerts")
    st.write(f"Found **{len(neighbor_alerts)}** related alerts.")

    if not neighbor_alerts:
        st.info("No neighbor alerts found for this alert.")
        return

    neighbor_box = st.container(height=320)

    with neighbor_box:
        h1, h2, h3, h4, h5 = st.columns([2, 2, 2, 4, 1])
        h1.markdown("**Timestamp**")
        h2.markdown("**Client**")
        h3.markdown("**Source IP**")
        h4.markdown("**Rule Description**")
        h5.markdown("**Severity**")

        st.divider()

        for neighbor in neighbor_alerts:
            c1, c2, c3, c4, c5 = st.columns([2, 2, 2, 4, 1])

            with c1:
                st.write(neighbor.get("timestamp", "unknown"))

            with c2:
                st.write(neighbor.get("agent_name", "unknown"))

            with c3:
                st.write(neighbor.get("source_ip", "unknown"))

            with c4:
                st.write(neighbor.get("rule_description", "unknown"))

            with c5:
                st.write(neighbor.get("severity", "unknown"))


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

st.divider()

st.subheader("Alerts")
st.markdown(
    '<div class="alerts-note">Scroll inside the alerts box to browse events, then scroll the page to view the investigation report.</div>',
    unsafe_allow_html=True
)

if st.session_state.alerts:
    alerts_box = st.container(height=520)

    with alerts_box:
        h1, h2, h3, h4, h5, h6 = st.columns([2, 2, 2, 4, 1, 1.2])
        h1.markdown("**Timestamp**")
        h2.markdown("**Client**")
        h3.markdown("**Source IP**")
        h4.markdown("**Rule Description**")
        h5.markdown("**Severity**")
        h6.markdown("**Action**")

        st.divider()

        for i, alert in enumerate(st.session_state.alerts):
            c1, c2, c3, c4, c5, c6 = st.columns([2, 2, 2, 4, 1, 1.2])

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
                if st.button("Analyze", key=f"analyze_{i}", use_container_width=True):
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
                        st.success("Analysis completed. Scroll down to view the report.")
                    except Exception as e:
                        st.error(f"Analysis failed: {e}")
else:
    st.info("No alerts loaded yet. Choose filters, then click 'Fetch Alerts'.")

if st.session_state.selected_alert:
    st.divider()
    render_selected_alert(st.session_state.selected_alert)

if st.session_state.selected_alert:
    st.divider()
    render_neighbor_alerts_table(st.session_state.neighbor_alerts)

if st.session_state.analysis_result:
    result = st.session_state.analysis_result

    st.divider()
    st.subheader("AI Incident Analysis")

    render_severity_box(result.get("ai_severity", "Unknown"))
    render_priority_box(result.get("ai_priority", "Unknown"))

    left, right = st.columns(2)

    with left:
        render_kv_box("Incident Type", str(result.get("incident_type", "unknown")))
        render_kv_box("Wazuh Severity", str(result.get("wazuh_severity", "unknown")))
        render_kv_box("AI Risk Score", f"{result.get('ai_risk_score', 'unknown')}/100")
        render_kv_box(
            "False Positive Likelihood",
            str(result.get("false_positive_likelihood", "unknown"))
        )

    with right:
        render_kv_box(
            "Needs Human Attention",
            str(result.get("needs_human_attention", "unknown"))
        )
        render_kv_box("Source IP", str(result.get("source_ip", "unknown")))
        render_kv_box("Target Host", str(result.get("target_host", "unknown")))
        render_kv_box("Neighbor Alerts Count", str(result.get("neighbor_alerts_count", "unknown")))
        render_kv_box("Confidence", str(result.get("confidence", "unknown")))

    st.subheader("Explanation")
    st.markdown(
        f"""
        <div class="section-box">
            {result.get("explanation", "No explanation returned.")}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Why It Matters")
    st.markdown(
        f"""
        <div class="section-box">
            {result.get("why_it_matters", "No impact explanation returned.")}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("Recommended Actions")
    actions = result.get("recommended_actions", [])
    if actions:
        for action in actions:
            st.markdown(
                f"""
                <div class="section-box">• {action}</div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.write("No actions returned.")

    st.subheader("Tools Used")
    tools_used = result.get("tools_used", [])
    if tools_used:
        badges_html = "".join(
            [f'<span class="mini-badge">{tool}</span>' for tool in tools_used]
        )
        st.markdown(badges_html, unsafe_allow_html=True)
    else:
        st.write("No external tools were used for this alert.")

    st.subheader("Tool Findings")
    render_tool_findings(result.get("tool_findings", []))


    # ----------------------------
# Threat Intelligence Demo
# ----------------------------

st.divider()
st.header("Threat Intelligence Demo")

st.write(
    "Test the AI agent with a public IP to see how it automatically uses "
    "AbuseIPDB and GreyNoise for threat intelligence enrichment."
)

demo_ip = st.text_input(
    "Enter a Public IP Address",
    placeholder="Example: 8.8.8.8"
)

run_demo = st.button("Run Threat Intelligence Demo")

if run_demo:

    if not demo_ip:
        st.warning("Please enter an IP address.")
    else:

        demo_alert = {
            "timestamp": "2026-03-11T00:00:00Z",
            "agent_name": "demo-host",
            "source_ip": demo_ip,
            "severity": 8,
            "rule_description": "Multiple SSH authentication failures detected from external IP"
        }

        demo_neighbors = [
    {
        "timestamp": "2026-03-11T00:00:01Z",
        "agent_name": "demo-host",
        "source_ip": demo_ip,
        "severity": 8,
        "rule_description": "SSH authentication failed"
    },
    {
        "timestamp": "2026-03-11T00:00:03Z",
        "agent_name": "demo-host",
        "source_ip": demo_ip,
        "severity": 8,
        "rule_description": "SSH authentication failed"
    }
]

        with st.spinner("AI agent analyzing the IP and calling threat intelligence tools..."):

            result = analyze_alert(
                demo_alert,
                demo_neighbors
            )

        st.subheader("AI Analysis Result")

        st.json(result)

        st.subheader("Tools Used")

        tools = result.get("tools_used", [])

        if tools:
            for t in tools:
                st.success(t)
        else:
            st.info("No external tools were used.")

        st.subheader("Tool Findings")

        findings = result.get("tool_findings", [])

        if findings:
            for f in findings:
                st.markdown(
                    f"""
                    **Tool:** {f.get("tool")}

                    **Observable:** {f.get("observable")}

                    **Finding:** {f.get("summary")}
                    """
                )
        else:
            st.info("No findings returned.")