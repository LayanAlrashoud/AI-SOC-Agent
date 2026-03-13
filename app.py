import json
import streamlit as st
from ai_agent import analyze_alert
from wazuh_client import get_latest_alert

st.set_page_config(page_title="AI SOC Dashboard", layout="wide")

st.title("AI SOC Analyst Dashboard")
st.write("Fetch the latest Wazuh alert and analyze it with OpenAI.")

if "alert_text" not in st.session_state:
    st.session_state.alert_text = ""

col1, col2 = st.columns(2)

with col1:
    if st.button("Fetch Latest Alert from Wazuh"):
        try:
            latest_alert = get_latest_alert()
            st.session_state.alert_text = json.dumps(latest_alert, indent=2)
            st.success("Latest alert loaded from Wazuh.")
        except Exception as e:
            st.error(f"Failed to fetch alert from Wazuh: {e}")

with col2:
    if st.button("Clear"):
        st.session_state.alert_text = ""

alert_text = st.text_area(
    "Wazuh Alert JSON",
    value=st.session_state.alert_text,
    height=320
)

if st.button("Analyze Alert"):
    try:
        alert = json.loads(alert_text)
        result = analyze_alert(alert)

        st.success("Analysis completed.")

        left, right = st.columns(2)

        with left:
            st.subheader("Latest Alert")
            st.json(alert)

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

    except json.JSONDecodeError:
        st.error("Invalid JSON.")
    except Exception as e:
        st.error(f"Unexpected error: {e}")