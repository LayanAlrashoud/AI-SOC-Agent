import os
import json
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_alert(alert: dict) -> dict:
    prompt = f"""
You are an expert SOC analyst.

Analyze the following Wazuh alert and return ONLY valid JSON.

Alert:
{json.dumps(alert, ensure_ascii=False, indent=2)}

Return this exact JSON structure:
{{
  "incident_type": "string",
  "severity": "Low | Medium | High | Critical",
  "explanation": "string",
  "recommended_actions": ["string", "string", "string"],
  "source_ip": "string",
  "target_host": "string",
  "confidence": 0.0
}}

Rules:
- Return valid JSON only.
- Do not add markdown.
- Do not add code fences.
- confidence must be a number between 0 and 1.
- If a field is missing, use "unknown".
"""

    response = client.responses.create(
        model="gpt-4o-mini",
        input=prompt
    )

    text = response.output_text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "incident_type": "Parsing Error",
            "severity": "Medium",
            "explanation": text,
            "recommended_actions": [
                "Review the raw AI output.",
                "Validate the alert manually.",
                "Improve prompt formatting."
            ],
            "source_ip": alert.get("source_ip", "unknown"),
            "target_host": alert.get("agent_name", "unknown"),
            "confidence": 0.5
        }