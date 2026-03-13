import os
import json
from dotenv import load_dotenv
from openai import OpenAI
from threat_tools import check_abuseipdb, check_greynoise

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL_NAME = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

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

Tool usage rules:
- If there is a public source IP and external reputation would help, call one or both tools:
  - check_abuseipdb
  - check_greynoise
- Do not call external IP tools for private, invalid, or loopback IPs.
- Use tool results as supporting evidence, not as the only decision factor.
"""

TOOLS = [
    {
        "type": "function",
        "name": "check_abuseipdb",
        "description": "Check the reputation of a public IP address using AbuseIPDB.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "Public IPv4 or IPv6 address to investigate."
                }
            },
            "required": ["ip"],
            "additionalProperties": False
        }
    },
    {
        "type": "function",
        "name": "check_greynoise",
        "description": "Check whether a public IP address is common internet background noise using GreyNoise.",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "Public IPv4 or IPv6 address to investigate."
                }
            },
            "required": ["ip"],
            "additionalProperties": False
        }
    }
]


def run_tool(name: str, args: dict) -> dict:
    if name == "check_abuseipdb":
        return check_abuseipdb(args.get("ip", ""))

    if name == "check_greynoise":
        return check_greynoise(args.get("ip", ""))

    return {
        "tool": name,
        "status": "error",
        "error": f"Unknown tool: {name}"
    }


def friendly_tool_name(tool_name: str) -> str:
    mapping = {
        "check_abuseipdb": "AbuseIPDB",
        "check_greynoise": "GreyNoise"
    }
    return mapping.get(tool_name, tool_name)


def is_private_like_ip(ip: str) -> bool:
    ip = (ip or "").strip()
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
    )


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
- If helpful, use the available tools.

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
  "confidence": 0.0,
  "tools_used": ["string"],
  "tool_findings": [
    {{
      "tool": "string",
      "observable": "string",
      "summary": "string"
    }}
  ]
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
- tools_used must contain the real tool names only if any tool was actually executed.
- tool_findings must reflect real executed tools only.
- If no tool was executed, leave tools_used empty and tool_findings empty.
"""

    try:
        response = client.responses.create(
            model=MODEL_NAME,
            instructions=SYSTEM_PROMPT,
            input=prompt,
            tools=TOOLS
        )

        max_rounds = 5
        rounds = 0

        executed_tools = []
        tool_outputs_memory = []

        while rounds < max_rounds:
            rounds += 1

            function_calls = [
                item for item in response.output
                if getattr(item, "type", "") == "function_call"
            ]

            if not function_calls:
                break

            tool_outputs = []

            for call in function_calls:
                tool_name = call.name

                try:
                    arguments = json.loads(call.arguments or "{}")
                except json.JSONDecodeError:
                    arguments = {}

                tool_result = run_tool(tool_name, arguments)

                executed_tools.append(friendly_tool_name(tool_name))
                tool_outputs_memory.append(tool_result)

                tool_outputs.append({
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": json.dumps(tool_result, ensure_ascii=False)
                })

            response = client.responses.create(
                model=MODEL_NAME,
                instructions=SYSTEM_PROMPT,
                previous_response_id=response.id,
                input=tool_outputs,
                tools=TOOLS
            )

        text = response.output_text.strip()
        result = json.loads(text)

        result["wazuh_severity"] = selected_alert.get("severity", 0)
        result["neighbor_alerts_count"] = len(neighbor_alerts)

        if not result.get("source_ip"):
            result["source_ip"] = selected_alert.get("source_ip", "unknown")

        if not result.get("target_host"):
            result["target_host"] = selected_alert.get("agent_name", "unknown")

        # deduplicate tool names from real executions only
        unique_tools = []
        for t in executed_tools:
            if t not in unique_tools:
                unique_tools.append(t)

        # if model invented values, ignore them unless the tool was really executed
        cleaned_findings = []

        if unique_tools:
            allowed_tool_names = set(unique_tools)

            raw_findings = result.get("tool_findings", [])
            if isinstance(raw_findings, list):
                for item in raw_findings:
                    if not isinstance(item, dict):
                        continue

                    tool_val = str(item.get("tool", "")).strip()
                    observable = item.get("observable", "")
                    summary = item.get("summary", "")

                    if tool_val in allowed_tool_names:
                        cleaned_findings.append({
                            "tool": tool_val,
                            "observable": observable or result.get("source_ip", "unknown"),
                            "summary": summary or "No summary provided."
                        })

        # if the model did not return usable findings, build them from actual tool outputs
        if unique_tools and not cleaned_findings and tool_outputs_memory:
            source_ip = selected_alert.get("source_ip", "unknown")

            for tool_result in tool_outputs_memory:
                tool_name = tool_result.get("tool", "unknown")
                status = tool_result.get("status", "unknown")

                if tool_name == "AbuseIPDB":
                    if status == "ok":
                        abuse_score = tool_result.get("abuse_confidence_score", "unknown")
                        total_reports = tool_result.get("total_reports", "unknown")
                        summary = (
                            f"AbuseIPDB reports abuse confidence score {abuse_score} "
                            f"with {total_reports} total reports for this IP."
                        )
                    elif status == "skipped":
                        summary = tool_result.get("message", "IP reputation check was skipped.")
                    elif status == "not_configured":
                        summary = "AbuseIPDB API key is not configured."
                    else:
                        summary = tool_result.get("error", "AbuseIPDB check failed.")

                    cleaned_findings.append({
                        "tool": "AbuseIPDB",
                        "observable": source_ip,
                        "summary": summary
                    })

                elif tool_name == "GreyNoise":
                    if status == "ok":
                        classification = tool_result.get("classification", "unknown")
                        noise = tool_result.get("noise", "unknown")
                        riot = tool_result.get("riot", "unknown")
                        summary = (
                            f"GreyNoise classification is {classification}; "
                            f"noise={noise}, riot={riot}."
                        )
                    elif status == "not_found":
                        summary = "GreyNoise has no community record for this IP."
                    elif status == "skipped":
                        summary = tool_result.get("message", "GreyNoise check was skipped.")
                    elif status == "not_configured":
                        summary = "GreyNoise API key is not configured."
                    else:
                        summary = tool_result.get("error", "GreyNoise check failed.")

                    cleaned_findings.append({
                        "tool": "GreyNoise",
                        "observable": source_ip,
                        "summary": summary
                    })

        # if no real external tool executed, show a clear skipped message for private/internal IPs
        source_ip = selected_alert.get("source_ip", "unknown")

        if not unique_tools:
            result["tools_used"] = []

            if is_private_like_ip(source_ip):
                result["tool_findings"] = [
                    {
                        "tool": "Internal Check",
                        "observable": source_ip,
                        "summary": "Skipped external enrichment because the source IP is private."
                    }
                ]
            else:
                result["tool_findings"] = []
        else:
            result["tools_used"] = unique_tools
            result["tool_findings"] = cleaned_findings

        return result

    except Exception as e:
        return {
            "incident_type": "Analysis Error",
            "wazuh_severity": selected_alert.get("severity", 0),
            "ai_severity": "Medium",
            "ai_risk_score": 50,
            "ai_priority": "P3",
            "false_positive_likelihood": "Medium",
            "needs_human_attention": "Yes",
            "explanation": f"Agent execution failed: {str(e)}",
            "why_it_matters": "The AI agent failed during analysis or tool execution.",
            "recommended_actions": [
                "Review the raw alert manually.",
                "Validate API keys and environment variables.",
                "Check tool-calling and JSON formatting."
            ],
            "source_ip": selected_alert.get("source_ip", "unknown"),
            "target_host": selected_alert.get("agent_name", "unknown"),
            "neighbor_alerts_count": len(neighbor_alerts),
            "confidence": 0.4,
            "tools_used": [],
            "tool_findings": []
        }