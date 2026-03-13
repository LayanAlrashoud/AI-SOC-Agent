import os
import json
import ipaddress
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

Tool usage rules:
- If there is a public source IP and external reputation would help, call one or both tools:
  - check_abuseipdb
  - check_greynoise
- Do not call external IP tools for private, invalid, loopback, multicast, reserved, or unspecified IPs.
- Use tool results as supporting evidence, not as the only decision factor.
"""

ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "incident_type": {"type": "string"},
        "wazuh_severity": {"type": "integer"},
        "ai_severity": {
            "type": "string",
            "enum": ["Low", "Medium", "High", "Critical"]
        },
        "ai_risk_score": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100
        },
        "ai_priority": {
            "type": "string",
            "enum": ["P1", "P2", "P3", "P4"]
        },
        "false_positive_likelihood": {
            "type": "string",
            "enum": ["Low", "Medium", "High"]
        },
        "needs_human_attention": {
            "type": "string",
            "enum": ["Yes", "No"]
        },
        "explanation": {"type": "string"},
        "why_it_matters": {"type": "string"},
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"}
        },
        "source_ip": {"type": "string"},
        "target_host": {"type": "string"},
        "neighbor_alerts_count": {"type": "integer"},
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "tools_used": {
            "type": "array",
            "items": {"type": "string"}
        },
        "tool_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "tool": {"type": "string"},
                    "observable": {"type": "string"},
                    "summary": {"type": "string"}
                },
                "required": ["tool", "observable", "summary"]
            }
        }
    },
    "required": [
        "incident_type",
        "wazuh_severity",
        "ai_severity",
        "ai_risk_score",
        "ai_priority",
        "false_positive_likelihood",
        "needs_human_attention",
        "explanation",
        "why_it_matters",
        "recommended_actions",
        "source_ip",
        "target_host",
        "neighbor_alerts_count",
        "confidence",
        "tools_used",
        "tool_findings"
    ]
}

TOOLS = [
    {
        "type": "function",
        "name": "check_abuseipdb",
        "description": "Check the reputation of a public IP address using AbuseIPDB.",
        "strict": True,
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
        "strict": True,
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

    if not ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def is_public_routable_ip(ip: str) -> bool:
    ip = (ip or "").strip()

    if not ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def get_structured_text_format() -> dict:
    return {
        "format": {
            "type": "json_schema",
            "name": "soc_alert_analysis",
            "strict": True,
            "schema": ANALYSIS_SCHEMA
        }
    }


def normalize_result(result: dict, selected_alert: dict, neighbor_alerts: list) -> dict:
    defaults = {
        "incident_type": "unknown",
        "wazuh_severity": int(selected_alert.get("severity", 0) or 0),
        "ai_severity": "Medium",
        "ai_risk_score": 50,
        "ai_priority": "P3",
        "false_positive_likelihood": "Medium",
        "needs_human_attention": "Yes",
        "explanation": "No explanation returned.",
        "why_it_matters": "No impact explanation returned.",
        "recommended_actions": [],
        "source_ip": str(selected_alert.get("source_ip", "unknown")),
        "target_host": str(selected_alert.get("agent_name", "unknown")),
        "neighbor_alerts_count": len(neighbor_alerts),
        "confidence": 0.5,
        "tools_used": [],
        "tool_findings": []
    }

    cleaned = {}

    for key, default_value in defaults.items():
        cleaned[key] = result.get(key, default_value)

    cleaned["wazuh_severity"] = int(selected_alert.get("severity", 0) or 0)
    cleaned["neighbor_alerts_count"] = len(neighbor_alerts)

    if not cleaned.get("source_ip"):
        cleaned["source_ip"] = str(selected_alert.get("source_ip", "unknown"))

    if not cleaned.get("target_host"):
        cleaned["target_host"] = str(selected_alert.get("agent_name", "unknown"))

    try:
        cleaned["ai_risk_score"] = int(cleaned["ai_risk_score"])
    except Exception:
        cleaned["ai_risk_score"] = 50
    cleaned["ai_risk_score"] = max(0, min(100, cleaned["ai_risk_score"]))

    try:
        cleaned["confidence"] = float(cleaned["confidence"])
    except Exception:
        cleaned["confidence"] = 0.5
    cleaned["confidence"] = max(0.0, min(1.0, cleaned["confidence"]))

    if not isinstance(cleaned.get("recommended_actions"), list):
        cleaned["recommended_actions"] = []

    if not isinstance(cleaned.get("tools_used"), list):
        cleaned["tools_used"] = []

    if not isinstance(cleaned.get("tool_findings"), list):
        cleaned["tool_findings"] = []

    return cleaned


def build_findings_from_tool_outputs(tool_outputs_memory: list, source_ip: str) -> list:
    findings = []

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

            findings.append({
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

            findings.append({
                "tool": "GreyNoise",
                "observable": source_ip,
                "summary": summary
            })

    return findings


def analyze_alert(
    selected_alert: dict,
    neighbor_alerts: list | None = None,
    force_tools: bool = False
) -> dict:
    if neighbor_alerts is None:
        neighbor_alerts = []

    payload = {
        "selected_alert": selected_alert,
        "neighbor_alerts_same_agent_same_ip_5min": neighbor_alerts
    }

    source_ip = str(selected_alert.get("source_ip", "unknown"))
    executed_tools = []
    tool_outputs_memory = []

    prompt = f"""
Analyze the selected Wazuh alert together with its neighboring alerts.

Important:
- The neighboring alerts are from the same client/agent and same source IP (when available) within a 5-minute time window.
- Use this surrounding context to detect attack patterns such as brute force, repeated authentication failures, privilege escalation, or benign admin activity.
- Your severity must be your own assessment, not just the original Wazuh severity.
- If repeated failed authentication events appear in the neighbor alerts, increase the AI severity accordingly.
- Use the available tools if helpful.

Input:
{json.dumps(payload, ensure_ascii=False, indent=2)}
"""

    try:
        if force_tools and is_public_routable_ip(source_ip):
            abuse_result = run_tool("check_abuseipdb", {"ip": source_ip})
            greynoise_result = run_tool("check_greynoise", {"ip": source_ip})

            tool_outputs_memory.extend([abuse_result, greynoise_result])
            executed_tools.extend(["AbuseIPDB", "GreyNoise"])

            prompt += f"""

Pre-fetched threat intelligence results:
{json.dumps(tool_outputs_memory, ensure_ascii=False, indent=2)}

Use these tool results as supporting evidence in your final assessment.
Do not invent additional tool outputs.
"""

            response = client.responses.create(
                model=MODEL_NAME,
                instructions=SYSTEM_PROMPT,
                input=prompt,
                text=get_structured_text_format()
            )
        else:
            response = client.responses.create(
                model=MODEL_NAME,
                instructions=SYSTEM_PROMPT,
                input=prompt,
                tools=TOOLS,
                text=get_structured_text_format()
            )

            max_rounds = 5
            rounds = 0

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
                    tools=TOOLS,
                    text=get_structured_text_format()
                )

        text = response.output_text.strip()
        result = json.loads(text)
        result = normalize_result(result, selected_alert, neighbor_alerts)

        unique_tools = []
        for tool_name in executed_tools:
            if tool_name not in unique_tools:
                unique_tools.append(tool_name)

        cleaned_findings = []

        if unique_tools:
            allowed_tool_names = set(unique_tools)
            raw_findings = result.get("tool_findings", [])

            if isinstance(raw_findings, list):
                for item in raw_findings:
                    if not isinstance(item, dict):
                        continue

                    tool_val = str(item.get("tool", "")).strip()
                    observable = str(item.get("observable", "") or "")
                    summary = str(item.get("summary", "") or "")

                    if tool_val in allowed_tool_names:
                        cleaned_findings.append({
                            "tool": tool_val,
                            "observable": observable or result.get("source_ip", "unknown"),
                            "summary": summary or "No summary provided."
                        })

        if unique_tools and not cleaned_findings and tool_outputs_memory:
            cleaned_findings = build_findings_from_tool_outputs(tool_outputs_memory, source_ip)

        if not unique_tools:
            result["tools_used"] = []

            if is_private_like_ip(source_ip):
                result["tool_findings"] = [
                    {
                        "tool": "Internal Check",
                        "observable": source_ip,
                        "summary": "Skipped external enrichment because the source IP is private or non-public."
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
            "wazuh_severity": int(selected_alert.get("severity", 0) or 0),
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
                "Check tool-calling and JSON schema formatting."
            ],
            "source_ip": selected_alert.get("source_ip", "unknown"),
            "target_host": selected_alert.get("agent_name", "unknown"),
            "neighbor_alerts_count": len(neighbor_alerts),
            "confidence": 0.4,
            "tools_used": [],
            "tool_findings": []
        }