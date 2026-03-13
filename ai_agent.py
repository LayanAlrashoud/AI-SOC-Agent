import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are Sentinel, a senior SOC analyst agent.

Your role is to triage and investigate security alerts like an experienced SOC analyst.
You are skeptical, precise, calm, and operationally practical.

Behavior rules:
- Think like a real human analyst in a SOC.
- Do not blindly trust the original Wazuh severity.
- Internal IP addresses are NOT automatically benign.
- Repeated authentication failures within a short time window may indicate brute force or credential guessing.
- Distinguish between routine admin activity and malicious or suspicious activity.
- Use the surrounding alert context to assess patterns, not only the selected event.
- Be concise, accurate, and professional.
- Return ONLY valid JSON.
"""


def analyze_alert(selected_alert: dict, neighbor_alerts: list | None = None) -> dict:
    if neighbor_alerts is None:
        neighbor_alerts = []

    payload = {
        "selected_alert": selected_alert,
        "neighbor_alerts_same_agent_same_ip_5min": neighbor_alerts
    }

    prompt = f"""
Analyze the following selected Wazuh alert together with its neighboring alerts.

Important:
- The neighboring alerts are from the same client/agent and same source IP (when available) within a 5-minute time window.
- Use this surrounding context to detect attack patterns such as brute force, repeated authentication failures, privilege escalation, or benign admin activity.
- Your severity must be YOUR own assessment, not just the original Wazuh severity.

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Return this exact JSON structure:
{{
  "incident_type": "string",
  "wazuh_severity": 0,
  "ai_severity": "Low | Medium | High | Critical",
  "ai_risk_score": 0,
  "ai_priority": "P1 | P2 | P3 | P4",
  "false_positive_likelihood": "Low | Medium | High",
  "needs_human_attention": "Yes | No",
  "explanation": "string",
  "why_it_matters": "string",
  "recommended_actions": ["string", "string", "string"],
  "source_ip": "string",
  "target_host": "string",
  "neighbor_alerts_count": 0,
  "confidence": 0.0
}}

Rules:
- Return valid JSON only.
- No markdown.
- No code fences.
- ai_risk_score must be an integer from 0 to 100.
- confidence must be a number between 0 and 1.
- wazuh_severity must reflect the selected alert's original severity.
- If a field is missing, use "unknown".
- If repeated failed authentication events appear in the neighbor alerts, increase the AI severity accordingly.
"""

    response = client.responses.create(
        model="gpt-4o-mini",
        instructions=SYSTEM_PROMPT,
        input=prompt
    )

    text = response.output_text.strip()

    try:
        result = json.loads(text)
        result["wazuh_severity"] = selected_alert.get("severity", 0)
        result["neighbor_alerts_count"] = len(neighbor_alerts)
        return result

    except json.JSONDecodeError:
        return {
            "incident_type": "Parsing Error",
            "wazuh_severity": selected_alert.get("severity", 0),
            "ai_severity": "Medium",
            "ai_risk_score": 50,
            "ai_priority": "P3",
            "false_positive_likelihood": "Medium",
            "needs_human_attention": "Yes",
            "explanation": text,
            "why_it_matters": "The AI response could not be parsed as valid JSON.",
            "recommended_actions": [
                "Review the raw AI output.",
                "Validate the alert manually.",
                "Improve prompt formatting."
            ],
            "source_ip": selected_alert.get("source_ip", "unknown"),
            "target_host": selected_alert.get("agent_name", "unknown"),
            "neighbor_alerts_count": len(neighbor_alerts),
            "confidence": 0.5
        }