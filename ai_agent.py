import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a senior SOC analyst agent working in a Security Operations Center.

Your personality and behavior:
- Be precise, calm, and professional.
- Think like an experienced SOC analyst, not a generic chatbot.
- Do not blindly trust the original Wazuh severity.
- Assess the security risk yourself based on context, behavior, privilege level, attack pattern, and operational impact.
- Distinguish between routine admin activity and suspicious or malicious activity.
- Be concise but insightful.
- Prioritize analyst attention on events that truly matter.
- Avoid exaggeration.
- If an alert looks benign or administrative, say so clearly.
- If an alert requires urgent attention, say so clearly.

Your task:
- Analyze a Wazuh alert.
- Produce a structured SOC assessment.
- Return ONLY valid JSON.
"""

def analyze_alert(alert: dict) -> dict:
    prompt = f"""
Analyze the following Wazuh alert.

Alert:
{json.dumps(alert, ensure_ascii=False, indent=2)}

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
  "confidence": 0.0
}}

Rules:
- Return valid JSON only.
- Do not add markdown.
- Do not add code fences.
- ai_risk_score must be an integer from 0 to 100.
- wazuh_severity must reflect the original Wazuh severity if available.
- confidence must be a number between 0 and 1.
- If a field is missing, use "unknown".
- Base your AI severity on your own judgment, not only on Wazuh severity.
- If this is likely routine admin activity, reflect that in false_positive_likelihood and needs_human_attention.
"""

    response = client.responses.create(
        model="gpt-5",
        instructions=SYSTEM_PROMPT,
        input=prompt
    )

    text = response.output_text.strip()

    try:
        result = json.loads(text)
        result["wazuh_severity"] = alert.get("severity", 0)
        return result

    except json.JSONDecodeError:
        return {
            "incident_type": "Parsing Error",
            "wazuh_severity": alert.get("severity", 0),
            "ai_severity": "Medium",
            "ai_risk_score": 50,
            "ai_priority": "P3",
            "false_positive_likelihood": "Medium",
            "needs_human_attention": "Yes",
            "explanation": text,
            "why_it_matters": "The AI response could not be parsed as valid structured JSON.",
            "recommended_actions": [
                "Review the raw AI output.",
                "Validate the alert manually.",
                "Improve prompt formatting."
            ],
            "source_ip": alert.get("source_ip", "unknown"),
            "target_host": alert.get("agent_name", "unknown"),
            "confidence": 0.5
        }