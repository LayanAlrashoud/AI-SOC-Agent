import os
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()
requests.packages.urllib3.disable_warnings()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")


def _post_search(query: dict):
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def _extract_source_ip(src: dict) -> str:
    candidates = [
        src.get("data", {}).get("srcip"),
        src.get("data", {}).get("src_ip"),
        src.get("data", {}).get("src_ip_address"),
        src.get("srcip"),
        src.get("agent", {}).get("ip"),
        src.get("win", {}).get("eventdata", {}).get("ipAddress"),
        src.get("win", {}).get("eventdata", {}).get("sourceAddress"),
        src.get("aws", {}).get("sourceIPAddress"),
        src.get("network", {}).get("src_ip"),
        src.get("network", {}).get("source_ip"),
    ]

    for value in candidates:
        if value and str(value).strip():
            return str(value).strip()

    return "N/A (local event)"


def _normalize_alert(src: dict, fallback_id="unknown"):
    return {
        "id": src.get("id", fallback_id),
        "timestamp": src.get("@timestamp", "unknown"),
        "rule_description": src.get("rule", {}).get("description", "unknown"),
        "source_ip": _extract_source_ip(src),
        "agent_name": src.get("agent", {}).get("name", "unknown"),
        "severity": src.get("rule", {}).get("level", 0),
        "full_log": src.get("full_log", "unknown"),
        "groups": src.get("rule", {}).get("groups", []),
        "mitre_ids": src.get("rule", {}).get("mitre", {}).get("id", []),
        "mitre_tactics": src.get("rule", {}).get("mitre", {}).get("tactic", []),
        "raw_alert": src
    }


def fetch_alerts(time_from="now-24h", agent_name=None, size=500):
    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": time_from
                }
            }
        }
    ]

    if agent_name and agent_name != "All":
        filters.append({
            "match_phrase": {
                "agent.name": agent_name.strip()
            }
        })

    query = {
        "size": size,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }

    data = _post_search(query)
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    for hit in hits:
        src = hit.get("_source", {})
        alerts.append(_normalize_alert(src, fallback_id=hit.get("_id", "unknown")))

    return alerts


def get_available_agents(size=300):
    alerts = fetch_alerts(time_from="now-30d", agent_name=None, size=size)
    agents = sorted(list({a["agent_name"] for a in alerts if a["agent_name"] != "unknown"}))
    return ["All"] + agents


def _parse_timestamp(ts: str):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def get_neighbor_alerts(selected_alert: dict, minutes=5, size=100):
    agent_name = selected_alert.get("agent_name", "unknown")
    source_ip = selected_alert.get("source_ip", "N/A (local event)")
    selected_time = selected_alert.get("timestamp")

    if not selected_time or selected_time == "unknown":
        return []

    center_dt = _parse_timestamp(selected_time)
    start_dt = center_dt - timedelta(minutes=minutes)
    end_dt = center_dt + timedelta(minutes=minutes)

    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": start_dt.astimezone(timezone.utc).isoformat(),
                    "lte": end_dt.astimezone(timezone.utc).isoformat()
                }
            }
        },
        {
            "match_phrase": {
                "agent.name": agent_name
            }
        }
    ]

    # فقط إذا كان عندنا source IP حقيقي
    if source_ip and source_ip not in ["unknown", "N/A (local event)"]:
        filters.append({
            "bool": {
                "should": [
                    {"match_phrase": {"data.srcip": source_ip}},
                    {"match_phrase": {"data.src_ip": source_ip}},
                    {"match_phrase": {"data.src_ip_address": source_ip}},
                    {"match_phrase": {"srcip": source_ip}},
                    {"match_phrase": {"win.eventdata.ipAddress": source_ip}},
                    {"match_phrase": {"win.eventdata.sourceAddress": source_ip}},
                    {"match_phrase": {"aws.sourceIPAddress": source_ip}},
                    {"match_phrase": {"network.src_ip": source_ip}},
                    {"match_phrase": {"network.source_ip": source_ip}}
                ],
                "minimum_should_match": 1
            }
        })

    query = {
        "size": size,
        "sort": [
            {"@timestamp": {"order": "asc"}}
        ],
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }

    data = _post_search(query)
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    selected_id = selected_alert.get("id")

    for hit in hits:
        src = hit.get("_source", {})
        normalized = _normalize_alert(src, fallback_id=hit.get("_id", "unknown"))

        if normalized["id"] != selected_id:
            alerts.append(normalized)

    return alerts